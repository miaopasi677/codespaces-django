from django.db import models
from django.contrib.auth.models import User

class CommunityRecord(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    data = models.TextField()  # 加密数据
    data_hash = models.CharField(max_length=64)  # 区块链哈希
    created_at = models.DateTimeField(auto_now_add=True)

class AuditLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    action = models.CharField(max_length=100)
    details = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)