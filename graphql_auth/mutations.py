import graphene
import graphql_jwt
from django.contrib.auth import get_user_model
from graphql_jwt.decorators import token_auth
from graphene.types.generic import GenericScalar
from graphql_jwt.settings import jwt_settings

from .bases import MutationMixin, DynamicArgsMixin
from .mixins import (
    RegisterMixin,
    VerifyAccountMixin,
    ResendActivationEmailMixin,
    SendPasswordResetEmailMixin,
    PasswordSetMixin,
    PasswordResetMixin,
    ObtainJSONWebTokenMixin,
    ArchiveAccountMixin,
    DeleteAccountMixin,
    PasswordChangeMixin,
    UpdateAccountMixin,
    VerifyOrRefreshOrRevokeTokenMixin,
    SendSecondaryEmailActivationMixin,
    VerifySecondaryEmailMixin,
    SwapEmailsMixin,
    RemoveSecondaryEmailMixin,
)
from .utils import normalize_fields
from .settings import graphql_auth_settings as app_settings
from .schema import UserNode

class CustomObtainJSONWebTokenMixin:
    payload = GenericScalar()
    refresh_expires_in = graphene.Int()

    @classmethod
    def Field(cls, *args, **kwargs):
        if not jwt_settings.JWT_HIDE_TOKEN_FIELDS:
            cls._meta.fields["token"] = graphene.Field(graphene.String)

            if jwt_settings.JWT_LONG_RUNNING_REFRESH_TOKEN:
                cls._meta.fields["refresh_token"] = graphene.Field(
                    graphene.String,
                )

        return super().Field(*args, **kwargs)

    @classmethod
    def __init_subclass_with_meta__(cls, name=None, **options):
        assert getattr(cls, "resolve", None), (
            f"{name or cls.__name__}.resolve "
            "method is required in a JSONWebTokenMutation."
        )

        super().__init_subclass_with_meta__(name=name, **options)

class JSONWebTokenMutation(CustomObtainJSONWebTokenMixin, graphene.Mutation):
    class Meta:
        abstract = True

    @classmethod
    def Field(cls, *args, **kwargs):
        cls._meta.arguments.update(
            {
                get_user_model().USERNAME_FIELD: graphene.String(required=True),
                "password": graphene.String(required=True),
            },
        )
        return super().Field(*args, **kwargs)

    @classmethod
    @token_auth
    def mutate(cls, root, info, **kwargs):
        return cls.resolve(root, info, **kwargs)

class Register(MutationMixin, DynamicArgsMixin, RegisterMixin, graphene.Mutation):

    __doc__ = RegisterMixin.__doc__

    password_fields = (
        []
        if app_settings.ALLOW_PASSWORDLESS_REGISTRATION
        else ["password1", "password2"]
    )
    _required_args = normalize_fields(
        app_settings.REGISTER_MUTATION_FIELDS, password_fields
    )
    _args = app_settings.REGISTER_MUTATION_FIELDS_OPTIONAL


class VerifyAccount(
    MutationMixin, DynamicArgsMixin, VerifyAccountMixin, graphene.Mutation
):
    __doc__ = VerifyAccountMixin.__doc__
    _required_args = ["token"]


class ResendActivationEmail(
    MutationMixin, DynamicArgsMixin, ResendActivationEmailMixin, graphene.Mutation
):
    __doc__ = ResendActivationEmailMixin.__doc__
    _required_args = ["email"]


class SendPasswordResetEmail(
    MutationMixin, DynamicArgsMixin, SendPasswordResetEmailMixin, graphene.Mutation
):
    __doc__ = SendPasswordResetEmailMixin.__doc__
    _required_args = ["email"]


class SendSecondaryEmailActivation(
    MutationMixin,
    DynamicArgsMixin,
    SendSecondaryEmailActivationMixin,
    graphene.Mutation,
):
    __doc__ = SendSecondaryEmailActivationMixin.__doc__
    _required_args = ["email", "password"]


class VerifySecondaryEmail(
    MutationMixin, DynamicArgsMixin, VerifySecondaryEmailMixin, graphene.Mutation
):
    __doc__ = VerifySecondaryEmailMixin.__doc__
    _required_args = ["token"]


class SwapEmails(MutationMixin, DynamicArgsMixin, SwapEmailsMixin, graphene.Mutation):
    __doc__ = SwapEmailsMixin.__doc__
    _required_args = ["password"]


class RemoveSecondaryEmail(
    MutationMixin, DynamicArgsMixin, RemoveSecondaryEmailMixin, graphene.Mutation
):
    __doc__ = RemoveSecondaryEmailMixin.__doc__
    _required_args = ["password"]


class PasswordSet(MutationMixin, PasswordSetMixin, DynamicArgsMixin, graphene.Mutation):
    __doc__ = PasswordSetMixin.__doc__
    _required_args = ["token", "new_password1", "new_password2"]


class PasswordReset(
    MutationMixin, DynamicArgsMixin, PasswordResetMixin, graphene.Mutation
):
    __doc__ = PasswordResetMixin.__doc__
    _required_args = ["token", "new_password1", "new_password2"]


class ObtainJSONWebToken(
    MutationMixin, ObtainJSONWebTokenMixin, JSONWebTokenMutation
):
    __doc__ = ObtainJSONWebTokenMixin.__doc__
    user = graphene.Field(UserNode)
    unarchiving = graphene.Boolean(default_value=False)


class ArchiveAccount(
    MutationMixin, ArchiveAccountMixin, DynamicArgsMixin, graphene.Mutation
):
    __doc__ = ArchiveAccountMixin.__doc__
    _required_args = ["password"]


class DeleteAccount(
    MutationMixin, DeleteAccountMixin, DynamicArgsMixin, graphene.Mutation
):
    __doc__ = DeleteAccountMixin.__doc__
    _required_args = ["password"]


class PasswordChange(
    MutationMixin, PasswordChangeMixin, DynamicArgsMixin, graphene.Mutation
):
    __doc__ = PasswordChangeMixin.__doc__
    _required_args = ["old_password", "new_password1", "new_password2"]


class UpdateAccount(
    MutationMixin, DynamicArgsMixin, UpdateAccountMixin, graphene.Mutation
):
    __doc__ = UpdateAccountMixin.__doc__
    _args = app_settings.UPDATE_MUTATION_FIELDS


class VerifyToken(MutationMixin, VerifyOrRefreshOrRevokeTokenMixin, graphql_jwt.Verify):
    __doc__ = VerifyOrRefreshOrRevokeTokenMixin.__doc__


class RefreshToken(
    MutationMixin, VerifyOrRefreshOrRevokeTokenMixin, graphql_jwt.Refresh
):
    __doc__ = VerifyOrRefreshOrRevokeTokenMixin.__doc__


class RevokeToken(MutationMixin, VerifyOrRefreshOrRevokeTokenMixin, graphql_jwt.Revoke):
    __doc__ = VerifyOrRefreshOrRevokeTokenMixin.__doc__
