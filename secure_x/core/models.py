from django.db import models
from django.conf import settings

class ScanHistory(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='scans')
    scan_type = models.CharField(max_length=20) # 'text', 'link', 'image'
    risk_level = models.CharField(max_length=20) # 'low', 'medium', 'high'
    risk_score = models.IntegerField(default=0)
    patterns = models.JSONField(blank=True, null=True) # store detected patterns as JSON
    is_resolved = models.BooleanField(default=False) # tracking whether the alert was handled
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user} - {self.scan_type} scanned ({self.risk_level})"
    
    class Meta:
        ordering = ['-created_at']

class CampusReport(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    report_id = models.CharField(max_length=50, unique=True, blank=True)
    incident_type = models.CharField(max_length=50)
    priority = models.CharField(max_length=20)
    title = models.CharField(max_length=150)
    description = models.TextField()
    contact_email = models.EmailField(blank=True, null=True)
    is_anonymous = models.BooleanField(default=False)
    campus = models.CharField(max_length=100)
    status = models.CharField(max_length=20, default='Pending') # Pending, Investigating, Resolved
    created_at = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.report_id:
            import datetime
            import random
            year = datetime.datetime.now().year
            rand = str(random.randint(0, 999)).zfill(3)
            self.report_id = f"REP-{year}-{rand}"
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.report_id} - {self.title}"
        
    class Meta:
        ordering = ['-created_at']

class ReportEvidence(models.Model):
    report = models.ForeignKey(CampusReport, related_name='evidences', on_delete=models.CASCADE)
    file = models.FileField(upload_to='report_evidence/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
