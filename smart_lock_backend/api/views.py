from rest_framework.decorators import api_view, action
from rest_framework import generics, viewsets, mixins
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth import authenticate, get_user_model
from django.db.models import Q
from .models import SmartLock, AccessPermission, AccessEventLog
from .serializers import (
    UserSerializer,
    UserRegisterSerializer,
    SmartLockSerializer,
    SmartLockDetailSerializer,
    AccessPermissionSerializer,
    AccessPermissionCreateSerializer,
    AccessEventLogSerializer,
)

User = get_user_model()


# PUBLIC_INTERFACE
@api_view(['GET'])
def health(request):
    """Health check. Returns up status."""
    return Response({"message": "Server is up!"})


# PUBLIC_INTERFACE
class UserRegisterView(generics.CreateAPIView):
    """User registration endpoint.

    POST: Register new user
    Payload: {username, email, password}
    """
    serializer_class = UserRegisterSerializer
    permission_classes = [AllowAny]


# PUBLIC_INTERFACE
class UserLoginView(APIView):
    """
    User login using username/email and password.

    POST: {username/email, password} returns JWT tokens
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(username=username, password=password)
        if not user:
            # Try email login fallback
            try:
                user = User.objects.get(email=username)
                if not user.check_password(password):
                    raise Exception()
            except Exception:
                return Response({"detail": "Invalid credentials."}, status=400)
        # Return SimpleJWT tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            "refresh": str(refresh),
            "access": str(refresh.access_token),
            "user": UserSerializer(user).data
        })


# PUBLIC_INTERFACE
class UserInfoView(APIView):
    """Get info for the currently authenticated user."""
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response(UserSerializer(request.user).data)


# PUBLIC_INTERFACE
class SmartLockViewSet(viewsets.ModelViewSet):
    """
    API endpoint to list, retrieve, create, update, and delete smart locks.
    Only lock owners or admins may manage locks. Non-owners can view locks with permission.
    """
    queryset = SmartLock.objects.all().order_by("-created_at")
    serializer_class = SmartLockSerializer
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.action == "retrieve":
            return SmartLockDetailSerializer
        return SmartLockSerializer

    def get_queryset(self):
        user = self.request.user
        # Show: locks owned, locks with any permission for, or all if admin/staff
        if user.is_superuser or user.is_staff:
            return SmartLock.objects.all().order_by("-created_at")
        owned = SmartLock.objects.filter(owner=user)
        perms = SmartLock.objects.filter(permissions__user=user)
        return (owned | perms).distinct().order_by("-created_at")

    def perform_create(self, serializer):
        instance = serializer.save(owner=self.request.user)
        # Creator always gets all permissions
        AccessPermission.objects.get_or_create(
            user=self.request.user,
            smart_lock=instance,
            defaults={"can_unlock": True, "can_lock": True, "can_view_logs": True, "granted_by": self.request.user}
        )
        AccessEventLog.objects.create(
            smart_lock=instance,
            user=self.request.user,
            event_type="added",
            message=f"Lock '{instance.name}' added."
        )

    @action(detail=True, methods=["post"])
    def lock(self, request, pk=None):
        """Lock the specified smart lock."""
        lock = self.get_object()
        perm = AccessPermission.objects.filter(user=request.user, smart_lock=lock).first()
        if not (request.user == lock.owner or (perm and perm.can_lock)):
            return Response({"detail": "Permission denied"}, status=403)
        lock.status = "locked"
        lock.save()
        AccessEventLog.objects.create(
            smart_lock=lock,
            user=request.user,
            event_type="lock",
            message=f"Locked {lock.name}"
        )
        return Response({"status": "locked"})

    @action(detail=True, methods=["post"])
    def unlock(self, request, pk=None):
        """Unlock the specified smart lock."""
        lock = self.get_object()
        perm = AccessPermission.objects.filter(user=request.user, smart_lock=lock).first()
        if not (request.user == lock.owner or (perm and perm.can_unlock)):
            return Response({"detail": "Permission denied"}, status=403)
        lock.status = "unlocked"
        lock.save()
        AccessEventLog.objects.create(
            smart_lock=lock,
            user=request.user,
            event_type="unlock",
            message=f"Unlocked {lock.name}"
        )
        return Response({"status": "unlocked"})

    @action(detail=True, methods=["get"])
    def status(self, request, pk=None):
        """Get real-time lock status."""
        lock = self.get_object()
        return Response({
            "status": lock.status,
            "is_online": lock.is_online,
            "updated": lock.created_at
        })

    @action(detail=True, methods=["get"])
    def activity_logs(self, request, pk=None):
        """Get logs for a smart lock."""
        lock = self.get_object()
        perm = AccessPermission.objects.filter(user=request.user, smart_lock=lock).first()
        owner = request.user == lock.owner
        if not (owner or (perm and perm.can_view_logs) or request.user.is_staff):
            return Response({"detail": "Permission denied"}, status=403)
        logs = AccessEventLog.objects.filter(smart_lock=lock).order_by("-timestamp")[:100]
        return Response(AccessEventLogSerializer(logs, many=True).data)


# PUBLIC_INTERFACE
class AccessPermissionViewSet(viewsets.ModelViewSet):
    """
    API endpoint to manage access permissions for locks.
    """
    queryset = AccessPermission.objects.all().select_related("user", "smart_lock")
    serializer_class = AccessPermissionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        # Admin/staff can see all; otherwise only what they own/granted
        if user.is_superuser or user.is_staff:
            return AccessPermission.objects.all()
        # Owns lock or granted by self or for self
        owned_lock_ids = SmartLock.objects.filter(owner=user).values_list("id", flat=True)
        return AccessPermission.objects.filter(
            Q(smart_lock__in=owned_lock_ids) | Q(user=user)
        ).distinct()

    def get_serializer_class(self):
        if self.action in ["create", "update", "partial_update"]:
            return AccessPermissionCreateSerializer
        return AccessPermissionSerializer

    def perform_create(self, serializer):
        perm = serializer.save(granted_by=self.request.user)
        # Log event
        msg = f"Permission granted to {perm.user.username} ({'unlock' if perm.can_unlock else ''} {'lock' if perm.can_lock else ''})"
        AccessEventLog.objects.create(
            smart_lock=perm.smart_lock,
            user=self.request.user,
            event_type="status_change",
            message=msg
        )


# PUBLIC_INTERFACE
class AccessEventLogViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    View for listing access logs.
    """
    queryset = AccessEventLog.objects.all().select_related("user", "smart_lock")
    serializer_class = AccessEventLogSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return AccessEventLog.objects.all()
        # See logs for locks user owns or has 'can_view_logs'
        lock_ids = list(SmartLock.objects.filter(owner=user).values_list("id", flat=True))
        perm_locks = AccessPermission.objects.filter(user=user, can_view_logs=True).values_list("smart_lock_id", flat=True)
        return AccessEventLog.objects.filter(smart_lock__in=list(lock_ids) + list(perm_locks)).order_by("-timestamp")

