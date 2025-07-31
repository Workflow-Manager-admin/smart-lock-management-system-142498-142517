from django.contrib import admin
from .models import User, SmartLock, AccessPermission, AccessEventLog

# Register your models here.
admin.site.register(User)
admin.site.register(SmartLock)
admin.site.register(AccessPermission)
admin.site.register(AccessEventLog)
