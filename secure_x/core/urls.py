from django.urls import path
from . import views


urlpatterns = [
    path('dashboard/', views.home, name='dashboard'),
    path('', views.home, name='home'),
    path('menu/', views.menu, name='menu'),
    path('scan/', views.scan, name='scan'),
    path('api/scan/', views.scan_api, name='scan_api'),
    path('web-protection/', views.web_protection, name='web-protection'),
    path('alerts/', views.alerts, name='alerts'),
    path('education/', views.education, name='education'),
    path('history/', views.history, name='history'),
    path('reports/', views.reports, name='reports'),
    path('verify-payment/', views.verify_payment, name='verify_payment'),
    path('settings/', views.settings_view, name='settings'),
    path('notifications/', views.notifications_view, name='notifications'),
    path('submit-report/', views.submit_report_view, name='submit_report'),
    
    # Alert APIs
    path('api/resolve_alert/<int:scan_id>/', views.resolve_alert, name='resolve_alert'),
    path('api/clear_alerts/', views.clear_alerts, name='clear_alerts'),
    
    # History API
    path('api/scan_details/<int:scan_id>/', views.get_scan_details, name='get_scan_details'),
    
    # Payment API
    path('api/verify_payment/', views.verify_payment_api, name='verify_payment_api'),
    
    # Reports API
    path('api/submit_report/', views.submit_report_api, name='submit_report_api'),
    path('api/report_details/<str:report_id>/', views.get_report_details, name='get_report_details'),

    # Profile API
    path('api/update_profile/', views.update_profile_api, name='update_profile_api'),
    path('api/delete_account/', views.delete_account_api, name='delete_account_api'),
    path('api/change_password/', views.change_password_api, name='change_password_api'),
]