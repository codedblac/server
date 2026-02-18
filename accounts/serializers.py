from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from .models import Address

User = get_user_model()


# ----------------------
# User Serializer
# ---------------------------
class UserSerializer(serializers.ModelSerializer):
    """Basic serializer for reading user data"""
    class Meta:
        model = User
        fields = ["id", "email", "full_name", "date_joined", "is_active"]
        read_only_fields = ["id", "date_joined", "is_active"]


# ---------------------------
# User Registration Serializer
# ---------------------------
class RegisterSerializer(serializers.ModelSerializer):
    """Serializer for user signup"""
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        style={"input_type": "password"},
        error_messages={"min_length": "Password must be at least 8 characters long."}
    )
    confirm_password = serializers.CharField(write_only=True, min_length=8, required=True)

    class Meta:
        model = User
        fields = ["email", "full_name", "password", "confirm_password"]

    def validate_email(self, value):
        value = User.objects.normalize_email(value)
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, data):
        if data["password"] != data["confirm_password"]:
            raise serializers.ValidationError({"confirm_password": "Passwords do not match."})
        return data

    def create(self, validated_data):
        validated_data.pop("confirm_password")
        try:
            user = User.objects.create_user(
                email=validated_data.get("email"),
                password=validated_data.get("password"),
                full_name=validated_data.get("full_name", "")
            )
            return user
        except Exception as e:
            raise serializers.ValidationError({"detail": str(e)})


# ---------------------------
# JWT Token Serializer
# ---------------------------
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Customize JWT login to include user info in response"""
    def validate(self, attrs):
        data = super().validate(attrs)
        data["user"] = UserSerializer(self.user).data
        return data


# ---------------------------
# User Profile Serializer
# ---------------------------
class UserProfileSerializer(serializers.ModelSerializer):
    """Read/update user profile"""
    class Meta:
        model = User
        fields = ["id", "email", "full_name", "date_joined"]
        read_only_fields = ["id", "email", "date_joined"]


# ---------------------------
# Password Reset Request Serializer
# ---------------------------
class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        # Always return success to prevent email enumeration
        return value


# ---------------------------
# Password Reset Confirm Serializer
# ---------------------------
class PasswordResetConfirmSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(
        min_length=8,
        style={"input_type": "password"},
        error_messages={"min_length": "Password must be at least 8 characters long."}
    )

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uidb64']))
            user = User.objects.get(pk=uid)
        except Exception:
            raise serializers.ValidationError({"uidb64": "Invalid or corrupted link."})

        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError({"token": "Invalid or expired token."})

        attrs['user'] = user
        return attrs

    def save(self):
        password = self.validated_data['new_password']
        user = self.validated_data['user']
        user.set_password(password)
        user.save()
        return user


# ---------------------------
# Address Serializer
# ---------------------------
class AddressSerializer(serializers.ModelSerializer):
    class Meta:
        model = Address
        fields = "__all__"
        read_only_fields = ["user", "created_at", "updated_at"]

    def validate(self, data):
        """
        Ensure only one default address per user
        """
        user = self.context["request"].user
        is_default = data.get("is_default", False)

        if is_default:
            qs = Address.objects.filter(user=user, is_default=True)
            if self.instance:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise serializers.ValidationError(
                    "Only one default address is allowed per user."
                )
        return data

    def create(self, validated_data):
        user = self.context["request"].user
        validated_data["user"] = user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        if validated_data.get("is_default", False):
            # Ensure only one default address
            Address.objects.filter(user=instance.user, is_default=True).exclude(pk=instance.pk).update(is_default=False)
        return super().update(instance, validated_data)
