from builtins import Exception, bool, classmethod, int, str
from datetime import datetime, timezone
import secrets
from sqlite3 import IntegrityError
from typing import Optional, Dict, List
from pydantic import ValidationError
from sqlalchemy import func, null, update, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from app.dependencies import get_email_service, get_settings
from app.models.user_model import User
from app.schemas.user_schemas import UserCreate, UserUpdate
from app.utils.nickname_gen import generate_nickname
from app.utils.security import generate_verification_token, hash_password, verify_password
from uuid import UUID
from app.services.email_service import EmailService
from app.models.user_model import UserRole
import logging

settings = get_settings()
logger = logging.getLogger(__name__)

class UserService:
    @classmethod
    async def _execute_query(cls, session: AsyncSession, query):
        try:
            result = await session.execute(query)
            await session.commit()
            return result
        except SQLAlchemyError as e:
            logger.error(f"Database error: {e}")
            await session.rollback()
            return None

    @classmethod
    async def _fetch_user(cls, session: AsyncSession, **filters) -> Optional[User]:
        query = select(User).filter_by(**filters)
        result = await cls._execute_query(session, query)
        return result.scalars().first() if result else None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: UUID) -> Optional[User]:
        return await cls._fetch_user(session, id=user_id)

    @classmethod
    async def get_by_nickname(cls, session: AsyncSession, nickname: str) -> Optional[User]:
        return await cls._fetch_user(session, nickname=nickname)

    @classmethod
    async def get_by_email(cls, session: AsyncSession, email: str) -> Optional[User]:
        return await cls._fetch_user(session, email=email)

    @classmethod
    async def create(cls, session: AsyncSession, user_data: Dict[str, str], email_service: EmailService) -> Optional[User]:
        # First check for email existence to avoid unnecessary processing
        existing_user = await cls.get_by_email(session, user_data.get('email'))
        if existing_user:
            logger.error("User with given email already exists.")
            return None

        # Check for password issues before creating the UserCreate model
        if 'password' not in user_data or not user_data['password']:
            logger.error("Password is required for user creation.")
            return 'PASSWORD_REQUIRED'

        if len(user_data['password'].strip()) < 8:  # Check if password length is too short
            logger.error("Password too short.")
            return 'PASSWORD_TOO_SHORT'

        # If all validations pass, proceed with creating the UserCreate model
        try:
            validated_data = UserCreate(**user_data).model_dump()

            # Handling password hashing
            validated_data['hashed_password'] = hash_password(user_data['password'])
            validated_data.pop('password', None)  # Remove plain password after hashing

            # Generate a unique nickname
            new_nickname = generate_nickname()
            while await cls.get_by_nickname(session, new_nickname):
                new_nickname = generate_nickname()
            validated_data['nickname'] = new_nickname

            # Determine user role
            user_count = await cls.count(session)
            validated_data['role'] = UserRole.ADMIN if user_count == 0 else UserRole.ANONYMOUS
            validated_data['email_verified'] = (validated_data['role'] == UserRole.ADMIN)
            if validated_data['role'] != UserRole.ADMIN:
                validated_data['verification_token'] = generate_verification_token()

            # Create and add new user to the database
            new_user = User(**validated_data)
            session.add(new_user)
            await session.commit()

            # Handle email verification for non-admin users
            if new_user.role != UserRole.ADMIN:
                try:
                    await email_service.send_verification_email(new_user)
                except Exception as e:
                    logger.error(f"Failed to send verification email: {e}")

            return new_user

        except ValidationError as e:
            logger.error(f"Validation error during user creation: {e}")
            return None

    @classmethod
    async def update(cls, session: AsyncSession, user_id: UUID, update_data: Dict[str, str]) -> Optional[User]:
        try:
            validated_data = UserUpdate(**update_data).model_dump(exclude_unset=True)

            # Handling email check and potential conflict
            if 'email' in validated_data:
                existing_user = await cls.get_by_email(session, validated_data['email'])
                if existing_user and existing_user.id != user_id:
                    logger.error("User with given email already exists.")
                    return 'EMAIL_EXISTS'  # Return a specific code or message as in the commented version

            # Handling password update by hashing the new password
            if 'password' in validated_data:
                validated_data['hashed_password'] = hash_password(validated_data.pop('password'))

            # Perform the update operation
            query = update(User).where(User.id == user_id).values(**validated_data).execution_options(synchronize_session="fetch")
            await cls._execute_query(session, query)
            updated_user = await cls.get_by_id(session, user_id)
            
            if updated_user:
                session.refresh(updated_user)  # Explicitly refresh the updated user object
                logger.info(f"User {user_id} updated successfully.")
                return updated_user
            else:
                logger.error(f"User {user_id} not found after update attempt.")
                return None
        except Exception as e:
            logger.error(f"Error during user update: {e}")
            return None  # Returning None as in the commented version for consistency

    @classmethod
    async def delete(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if not user:
            logger.info(f"User with ID {user_id} not found.")
            return False
        await session.delete(user)
        await session.commit()
        return True

    @classmethod
    async def list_users(cls, session: AsyncSession, skip: int = 0, limit: int = 10) -> List[User]:
        if skip < 0:
            skip = 0  # Ensure skip is not negative
        if limit < 1:
            limit = 1  # Ensure limit is at least 1
        query = select(User).offset(skip).limit(limit)
        result = await cls._execute_query(session, query)
        return result.scalars().all() if result else []

    @classmethod
    async def register_user(cls, session: AsyncSession, user_data: Dict[str, str], get_email_service) -> Optional[User]:
        return await cls.create(session, user_data, get_email_service)
    

    @classmethod
    async def login_user(cls, session: AsyncSession, email: str, password: str) -> Optional[User]:
        user = await cls.get_by_email(session, email)
        if user:
            if user.email_verified is False:
                return None
            if user.is_locked:
                return None
            if verify_password(password, user.hashed_password):
                user.failed_login_attempts = 0
                user.last_login_at = datetime.now(timezone.utc)
                session.add(user)
                await session.commit()
                return user
            else:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= settings.max_login_attempts:
                    user.is_locked = True
                session.add(user)
                await session.commit()
        return None

    @classmethod
    async def is_account_locked(cls, session: AsyncSession, email: str) -> bool:
        user = await cls.get_by_email(session, email)
        return user.is_locked if user else False


    @classmethod
    async def reset_password(cls, session: AsyncSession, user_id: UUID, new_password: str) -> bool:
        hashed_password = hash_password(new_password)
        user = await cls.get_by_id(session, user_id)
        if user:
            user.hashed_password = hashed_password
            user.failed_login_attempts = 0  # Resetting failed login attempts
            user.is_locked = False  # Unlocking the user account, if locked
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def verify_email_with_token(cls, session: AsyncSession, user_id: UUID, token: str) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.verification_token == token:
            user.email_verified = True
            user.verification_token = None  # Clear the token once used
            user.role = UserRole.AUTHENTICATED
            session.add(user)
            await session.commit()
            return True
        return False

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        """
        Count the number of users in the database.

        :param session: The AsyncSession instance for database access.
        :return: The count of users.
        """
        query = select(func.count()).select_from(User)
        result = await session.execute(query)
        count = result.scalar()
        return count
    
    @classmethod
    async def unlock_user_account(cls, session: AsyncSession, user_id: UUID) -> bool:
        user = await cls.get_by_id(session, user_id)
        if user and user.is_locked:
            user.is_locked = False
            user.failed_login_attempts = 0  # Optionally reset failed login attempts
            session.add(user)
            await session.commit()
            return True
        return False
