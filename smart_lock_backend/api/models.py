from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

# PUBLIC_INTERFACE
class User(AbstractUser):
    """Custom user, supporting username and email login."""
    # Extend/override as needed for extra fields (e.g. phone)
    pass


# PUBLIC_INTERFACE
class SmartLock(models.Model):
    """
    Model representing a smart lock device.
    """
    name = models.CharField(max_length=100)
    location = models.CharField(max_length=1024, blank=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=32, default="locked", choices=[("locked", "Locked"), ("unlocked", "Unlocked")])
    is_online = models.BooleanField(default=True)
    owner = models.ForeignKey(User, related_name="owned_locks", on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} ({self.location})"


# PUBLIC_INTERFACE
class AccessPermission(models.Model):
    """
    Manages which user can operate (lock/unlock/view) a smart lock.
    """
    user = models.ForeignKey(User, related_name="access_permissions", on_delete=models.CASCADE)
    smart_lock = models.ForeignKey(SmartLock, related_name="permissions", on_delete=models.CASCADE)
    can_unlock = models.BooleanField(default=False)
    can_lock = models.BooleanField(default=False)
    can_view_logs = models.BooleanField(default=False)  # e.g., regular vs admin
    granted_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="granted_permissions")
    granted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'smart_lock')


# PUBLIC_INTERFACE
class AccessEventLog(models.Model):
    """
    Log of all access events (unlocks, locks, status changes).
    """
    EVENT_CHOICES = [
        ("unlock", "Unlock"),
        ("lock", "Lock"),
        ("access_denied", "Access denied"),
        ("added", "Lock added"),
        ("status_change", "Status change"),
    ]
    smart_lock = models.ForeignKey(SmartLock, related_name="logs", on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name="access_logs", on_delete=models.SET_NULL, null=True, blank=True)
    event_type = models.CharField(max_length=32, choices=EVENT_CHOICES)
    message = models.CharField(max_length=256, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.smart_lock.name} - {self.event_type} by {self.user} at {self.timestamp}"

