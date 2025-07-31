from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import SmartLock, AccessPermission, AccessEventLog

User = get_user_model()

# PUBLIC_INTERFACE
class UserSerializer(serializers.ModelSerializer):
    """Serializer for user information."""

    class Meta:
        model = User
        fields = ("id", "username", "email", "is_superuser", "is_staff")
        read_only_fields = ("id", "is_superuser", "is_staff")


class UserRegisterSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ("id", "username", "email", "password")

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data.get("email", ""),
            password=validated_data["password"],
        )
        return user


# PUBLIC_INTERFACE
class SmartLockSerializer(serializers.ModelSerializer):
    """Serializer for SmartLock objects."""
    owner = UserSerializer(read_only=True)

    class Meta:
        model = SmartLock
        fields = ("id", "name", "location", "description", "status", "is_online", "owner", "created_at")
        read_only_fields = ("id", "owner", "created_at")


class SmartLockDetailSerializer(serializers.ModelSerializer):
    """Serializer with detailed permission info."""
    owner = UserSerializer(read_only=True)
    permissions = serializers.SerializerMethodField()

    class Meta:
        model = SmartLock
        fields = ("id", "name", "location", "description", "status", "is_online", "owner", "created_at", "permissions")

    def get_permissions(self, obj):
        perms = AccessPermission.objects.filter(smart_lock=obj)
        return AccessPermissionSerializer(perms, many=True).data


# PUBLIC_INTERFACE
class AccessPermissionSerializer(serializers.ModelSerializer):
    """Serializer for access permissions."""
    user = UserSerializer(read_only=True)
    smart_lock = serializers.PrimaryKeyRelatedField(read_only=True)

    class Meta:
        model = AccessPermission
        fields = ("id", "user", "smart_lock", "can_unlock", "can_lock", "can_view_logs", "granted_by", "granted_at")
        read_only_fields = ("id", "granted_by", "granted_at", "user", "smart_lock")


class AccessPermissionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating/editing permissions."""

    class Meta:
        model = AccessPermission
        fields = ("user", "smart_lock", "can_unlock", "can_lock", "can_view_logs")

    def validate(self, attrs):
        # Prevent granting permission to oneself as admin unless superuser
        if self.context["request"].user == attrs.get("user") and not self.context["request"].user.is_superuser:
            raise serializers.ValidationError("Cannot grant permissions to yourself.")
        return attrs


# PUBLIC_INTERFACE
class AccessEventLogSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    smart_lock = serializers.PrimaryKeyRelatedField(read_only=True)
    class Meta:
        model = AccessEventLog
        fields = ("id", "smart_lock", "user", "event_type", "message", "timestamp")
        read_only_fields = ("id", "timestamp", "user", "smart_lock")
