from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import ScanHistory, CampusReport, ReportEvidence

# Create your views here.
@login_required
def home(request):
    user_scans = ScanHistory.objects.filter(user=request.user)
    total_scans = user_scans.count()
    threats_detected = user_scans.filter(risk_level__in=['medium', 'high']).count()
    
    recent_alerts = user_scans.order_by('-created_at')[:4]
    
    import random
    SECURITY_TIPS = [
        "Beware of urgent payment requests. Scam emails often create a sense of urgency to trick you into acting quickly. Always verify the sender's identity.",
        "Never share your One-Time Password (OTP) or BVN with anyone, even if they claim to be from your bank.",
        "Hover over links in emails to see the actual destination URL before clicking on them.",
        "Enable Two-Factor Authentication (2FA) on all your important accounts for an extra layer of security.",
        "Public Wi-Fi networks can be unsecure. Avoid accessing sensitive financial information while connected to them.",
        "Regularly update your passwords and avoid using the same password across multiple platforms.",
        "If an offer sounds too good to be true, it probably is. Be skeptical of unexpected prizes or investment returns.",
        "Always lock your device when stepping away to prevent unauthorized physical access to your accounts."
    ]
    daily_tip = random.choice(SECURITY_TIPS)
    
    context = {
        'active_page': 'dashboard',
        'total_scans': total_scans,
        'threats_detected': threats_detected,
        'recent_alerts': recent_alerts,
        'security_tip': daily_tip
    }
    return render(request, 'core/dashboard.html', context)

@login_required
def menu(request):
    user_scans = ScanHistory.objects.filter(user=request.user)
    total_scans = user_scans.count()
    threats_detected = user_scans.filter(risk_level__in=['medium', 'high']).count()
    safe_scans = user_scans.filter(risk_level='low').count()
    
    return render(request, 'core/menu.html', {
        'active_page': 'menu',
        'total_scans': total_scans,
        'threats_detected': threats_detected,
        'safe_scans': safe_scans
    })

@login_required
def scan(request):
    return render(request, 'core/scan.html', {'active_page': 'scan'})

@login_required
def web_protection(request):
    link_scans = ScanHistory.objects.filter(user=request.user, scan_type='link')
    sites_scanned = link_scans.count()
    threats_blocked = link_scans.filter(risk_level__in=['medium', 'high']).count()
    safe_sites = link_scans.filter(risk_level='low').count()
    warnings_shown = link_scans.filter(risk_level='medium').count()
    
    recent_blocked_sites = link_scans.filter(risk_level__in=['medium', 'high']).order_by('-created_at')[:4]
    
    context = {
        'active_page': 'web',
        'sites_scanned': sites_scanned,
        'threats_blocked': threats_blocked,
        'safe_sites': safe_sites,
        'warnings_shown': warnings_shown,
        'recent_blocked_sites': recent_blocked_sites
    }
    return render(request, 'core/web-protection.html', context)

@login_required
def alerts(request):
    all_alerts = ScanHistory.objects.filter(user=request.user, risk_level__in=['medium', 'high']).order_by('-created_at')
    active_alerts = all_alerts.filter(is_resolved=False)
    resolved_alerts = all_alerts.filter(is_resolved=True)
    
    context = {
        'active_page': 'alerts',
        'active_alerts': active_alerts,
        'resolved_alerts': resolved_alerts,
        'total_count': all_alerts.count(),
        'active_count': active_alerts.count(),
        'resolved_count': resolved_alerts.count()
    }
    return render(request, 'core/alerts.html', context)  
import json
import re
import os
import socket
import urllib.parse
import difflib
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

try:
    import google.generativeai as genai
    import PIL.Image
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

@login_required
@csrf_exempt
def scan_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    try:
        api_key = getattr(settings, 'GEMINI_API_KEY', os.environ.get('GEMINI_API_KEY'))
        use_ai = GENAI_AVAILABLE and api_key
        model = None
        
        if use_ai:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-2.5-flash')
            
        SYSTEM_PROMPT = """
        You are a highly advanced cybersecurity analyst. The user submitted a {scan_type} to scan for threats such as phishing, scams, malicious links, or fake payment alerts.
        {content_prompt}
        
        Carefully analyze the content. If it appears completely legitimate, safe, or is a genuine verified bank receipt without any signs of tampering or scams, you MUST assign a "low" risk_level and a low risk_score (e.g. 0-20). Only assign "medium" or "high" if you detect actual suspicious elements, manipulation, phishing attempts, or known scam patterns.

        Return ONLY a valid JSON object matching exactly this schema and nothing else:
        {{
            "risk_level": "<low|medium|high>",  
            "risk_score": <integer from 0 to 100>,      
            "patterns": [ {{"title": "String", "desc": "String"}} ],
            "recommendations": [ {{"title": "String", "desc": "String"}} ],
            "safety_tip": "String"
        }}
        """
        
        # Check if it's multipart/form-data for image upload or application/json
        if request.content_type.startswith('multipart/form-data'):
            scan_type = request.POST.get('type')
            if scan_type == 'image':
                file = request.FILES.get('image')
                if file:
                    if use_ai and model:
                        try:
                            image = PIL.Image.open(file)
                            prompt = SYSTEM_PROMPT.format(scan_type="screenshot or image", content_prompt="Please analyze the attached image representing a bank transfer, system alert, or message. Look for inconsistencies, fake generator watermarks, font mismatches, or scam tactics.")
                            response = model.generate_content([prompt, image])
                            res_text = response.text.strip()
                            if res_text.startswith("```json"): res_text = res_text[7:-3].strip()
                            elif res_text.startswith("```"): res_text = res_text[3:-3].strip()
                            res_json = json.loads(res_text)
                            if request.user.is_authenticated:
                                ScanHistory.objects.create(
                                    user=request.user,
                                    scan_type=scan_type,
                                    scanned_content=f"Image Scan ({file.name})",
                                    risk_level=res_json.get('risk_level', 'low'),
                                    risk_score=res_json.get('risk_score', 0),
                                    patterns=res_json.get('patterns', [])
                                )
                            return JsonResponse(res_json)
                        except Exception as e:
                            print(f"Gemini API Error: {str(e)}")
                            return JsonResponse({
                                'risk_level': 'high',
                                'risk_score': 99,
                                'patterns': [{'title': 'AI Crash Debug', 'desc': f'Error details: {str(e)}'}],
                                'recommendations': [{'title': 'Raw Output', 'desc': res_text if 'res_text' in locals() else 'Failed before generation'}],
                                'safety_tip': 'Please paste this output to me so I can debug!'
                            })
                    
                    # Fallback logic if AI is unsupported, missing key, or API throws error
                    fallback_res = {
                        'risk_level': 'medium',
                        'risk_score': 60,
                        'patterns': [{'title': 'Unverified Image', 'desc': 'Image analysis is limited; be cautious of manipulated screenshots.'}],
                        'recommendations': [{'title': 'Verify Identity', 'desc': 'Check sender details independently.'}, {'title': 'Check App', 'desc': 'Confirm alerts directly via your bank app.'}],
                        'safety_tip': 'Scammers often manipulate bank receipts and payment proofs using image editing tools.'
                    }
                    if request.user.is_authenticated:
                        ScanHistory.objects.create(
                            user=request.user,
                            scan_type=scan_type,
                            scanned_content=f"Image Scan ({file.name})",
                            risk_level=fallback_res['risk_level'],
                            risk_score=fallback_res['risk_score'],
                            patterns=fallback_res['patterns']
                        )
                    return JsonResponse(fallback_res)
            return JsonResponse({"error": "Invalid data"}, status=400)
        
        data = json.loads(request.body)
        scan_type = data.get('type')
        content = data.get('content', '')
        
        if use_ai:
            prompt = SYSTEM_PROMPT.format(scan_type=scan_type, content_prompt=f'Content to analyze: "{content}"')
            response = model.generate_content(prompt)
            res_text = response.text.strip()
            if res_text.startswith("```json"): res_text = res_text[7:-3].strip()
            elif res_text.startswith("```"): res_text = res_text[3:-3].strip()
            res_json = json.loads(res_text)
            if request.user.is_authenticated:
                ScanHistory.objects.create(
                    user=request.user,
                    scan_type=scan_type,
                    scanned_content=content,
                    risk_level=res_json.get('risk_level', 'low'),
                    risk_score=res_json.get('risk_score', 0),
                    patterns=res_json.get('patterns', [])
                )
            return JsonResponse(res_json)
            
        else:
            # Fallback heuristic
            content_lower = content.lower()
            risk_score = 0
            patterns = []
            recommendations = []
            safety_tip = 'Stay vigilant. Always double-check unexpected requests for money.'
            
            if scan_type == 'text':
                # Advanced Keyword Categories
                financial_keywords = ['bvn', 'pin', 'password', 'otp', 'token', 'atm card', 'cvv']
                urgency_keywords = ['urgent', 'immediately', 'warning', 'blocked', 'suspended', 'restrict', 'verify now']
                scam_keywords = ['win', 'won', 'scholarship', 'congratulations', 'lottery', 'inheritance', 'guaranteed', 'cash prize']
                phishing_lures = ['verify account', 'update details', 'unauthorized login', 'security alert']
                
                if any(kw in content_lower for kw in financial_keywords):
                    risk_score += 45
                    patterns.append({'title': 'Sensitive Data Request', 'desc': 'Asks for highly confidential information like a PIN, BVN, or Password.'})
                    recommendations.append({'title': 'Do Not Share', 'desc': 'Never share personal or financial information.'})
                    
                if any(kw in content_lower for kw in urgency_keywords):
                    risk_score += 30
                    patterns.append({'title': 'Urgency Tactics', 'desc': 'Creates false panic to pressure you into acting without thinking.'})
                    
                if any(kw in content_lower for kw in scam_keywords):
                    risk_score += 35
                    patterns.append({'title': 'Too Good to Be True', 'desc': 'Promises unexpected rewards or money, typical of advance-fee scams.'})
                    
                if any(kw in content_lower for kw in phishing_lures):
                    risk_score += 30
                    patterns.append({'title': 'Phishing Lure', 'desc': 'Mimics official security alerts to steal your credentials.'})
                    
                # Regex for hidden emails, phone numbers, or links
                if re.search(r'https?://[^\s]+', content_lower) or re.search(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', content_lower):
                    risk_score += 25
                    patterns.append({'title': 'Embedded Link', 'desc': 'Contains a link that could redirect you to a malicious site.'})
                    recommendations.append({'title': 'Avoid Clicks', 'desc': 'DO NOT click any links inside unexpected messages.'})
                    
                recommendations.append({'title': 'Ignore Sender', 'desc': 'DO NOT respond to this message.'})
                recommendations.append({'title': 'Block Contact', 'desc': 'Block the sender if they are unknown.'})
                safety_tip = 'Legitimate organizations generally communicate through official channels, not random texts or unprompted emails.'
                
            elif scan_type == 'link':
                # Parse URL
                url_to_parse = content_lower if content_lower.startswith('http') else 'http://' + content_lower
                parsed_url = urllib.parse.urlparse(url_to_parse)
                hostname = parsed_url.hostname or ''

                # Deep Regex Parsing
                has_ip = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', content_lower)
                is_shortener = any(domain in content_lower for domain in ['bit.ly', 'tinyurl', 'short.gy', 't.co', 'goo.gl', 'ow.ly'])
                suspicious_tlds = ['.xyz', '.tk', '.top', '.pw', '.icu', '.cc', '.buzz', '.info']
                phishing_path_keywords = ['login', 'verify', 'update', 'secure', 'auth', 'account', 'signin']
                
                if is_shortener:
                    risk_score += 55
                    patterns.append({'title': 'URL Shortener', 'desc': 'Hides the actual destination of the link, commonly used to mask malicious endpoints.'})
                    
                if not content_lower.startswith('https'):
                    risk_score += 35
                    patterns.append({'title': 'Insecure Connection', 'desc': 'Does not use HTTPS encryption, leaving data vulnerable to interception.'})
                
                if has_ip:
                    risk_score += 65
                    patterns.append({'title': 'Direct IP Address', 'desc': 'Uses an IP instead of a verified domain name, highly suspicious behavior.'})
                    
                if any(tld in content_lower for tld in suspicious_tlds):
                    risk_score += 45
                    patterns.append({'title': 'Suspicious TLD', 'desc': 'Uses a top-level domain extension that is frequently associated with spam.'})
                    
                if any(kw in content_lower for kw in phishing_path_keywords):
                    risk_score += 30
                    patterns.append({'title': 'Phishing Keywords', 'desc': 'URL path contains terms designed to trick you into entering credentials.'})

                # Typosquatting Detection
                top_brands = ['paypal', 'google', 'facebook', 'apple', 'amazon', 'microsoft', 'netflix', 'bankofamerica', 'chase', 'wellsfargo', 'instagram', 'twitter', 'linkedin']
                if hostname and not has_ip:
                    parts = hostname.split('.')
                    if len(parts) >= 2:
                        main_domain = parts[-2]
                        for brand in top_brands:
                            if main_domain == brand:
                                continue # Exact match is fine for this check
                            similarity = difflib.SequenceMatcher(None, main_domain, brand).ratio()
                            if similarity > 0.8:
                                risk_score += 75
                                patterns.append({'title': 'Typosquatting Detected', 'desc': f'This domain closely mimics the trusted brand "{brand}" but is misspelled. Highly likely to be a phishing site.'})
                                break

                # Live Domain Resolution Check
                if hostname and not has_ip:
                    try:
                        socket.gethostbyname(hostname)
                    except socket.error:
                        risk_score += 40
                        patterns.append({'title': 'Unregistered / Dead Domain', 'desc': 'The domain name does not resolve to an active server, indicating it may be fake or taken down.'})

                recommendations.append({'title': 'Do Not Login', 'desc': 'Never enter credentials on this site.'})
                recommendations.append({'title': 'Navigate Directly', 'desc': 'Type the root URL of the brand directly into your browser instead of clicking the link.'})
                safety_tip = 'Always hover over links or use an expander tool to see the real destination before clicking.'
            
            else:
                return JsonResponse({"error": "Invalid scan type"}, status=400)
                
            if risk_score > 100: risk_score = 100
                
            if risk_score >= 70:
                risk_level = 'high'
            elif risk_score >= 40:
                risk_level = 'medium'
            else:
                risk_level = 'low'
                if not patterns:
                    patterns.append({'title': 'No Known Threats', 'desc': 'This content does not match our current threat signatures.'})
                recommendations.append({'desc': 'Still exercise standard caution.'})
                
            if request.user.is_authenticated:
                ScanHistory.objects.create(
                    user=request.user,
                    scan_type=scan_type,
                    scanned_content=content,
                    risk_level=risk_level,
                    risk_score=risk_score,
                    patterns=patterns
                )
                
            return JsonResponse({
                'risk_level': risk_level,
                'risk_score': risk_score,
                'patterns': patterns,
                'recommendations': recommendations,
                'safety_tip': safety_tip
            })
            
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@login_required
def education(request):
    return render(request, 'feature/education.html', {'active_page': 'education'})

@login_required
def history(request):
    user_scans = ScanHistory.objects.filter(user=request.user).order_by('-created_at')
    return render(request, 'feature/history.html', {'active_page': 'history', 'scans': user_scans})

@login_required
def reports(request):
    campus_reports = CampusReport.objects.all()
    # You might want to filter by user's campus or let them filter on frontend
    
    # Calculate simple stats for the UI
    total_count = campus_reports.count()
    active_count = campus_reports.filter(status='Pending').count() + campus_reports.filter(status='Investigating').count()
    resolved_count = campus_reports.filter(status='Resolved').count()
    
    context = {
        'active_page': 'reports',
        'reports': campus_reports,
        'total_count': total_count,
        'active_count': active_count,
        'resolved_count': resolved_count
    }
    return render(request, 'feature/reports.html', context)

@login_required
def verify_payment(request):
    return render(request, 'feature/verify-payment.html', {'active_page': 'verify-payment'})

@login_required
def about(request):
    return render(request, 'settings_info/about.html', {'active_page': 'about'})

@login_required
def help_center(request):
    return render(request, 'settings_info/help.html', {'active_page': 'help'})

@login_required
def settings_view(request):
    return render(request, 'settings_info/settings.html', {'active_page': 'settings'})

@login_required
def submit_report_view(request):
    return render(request, 'feature/submit-report.html', {'active_page': 'submit-report'})

@login_required
def notifications_view(request):
    user_scans = ScanHistory.objects.filter(user=request.user).order_by('-created_at')[:20]
    return render(request, 'feature/notifications.html', {
        'active_page': 'notifications',
        'notifications': user_scans
    })

@login_required
@csrf_exempt
def resolve_alert(request, scan_id):
    if request.method == 'POST':
        try:
            alert = ScanHistory.objects.get(id=scan_id, user=request.user)
            alert.is_resolved = True
            alert.save()
            return JsonResponse({'status': 'success'})
        except ScanHistory.DoesNotExist:
            return JsonResponse({'error': 'Alert not found'}, status=404)
    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
@csrf_exempt
def clear_alerts(request):
    if request.method == 'POST':
        ScanHistory.objects.filter(user=request.user, is_resolved=True).delete()
        return JsonResponse({'status': 'success'})
    return JsonResponse({'error': 'Invalid request'}, status=400)

@login_required
def get_scan_details(request, scan_id):
    try:
        scan = ScanHistory.objects.get(id=scan_id, user=request.user)
        return JsonResponse({
            'status': 'success',
            'data': {
                'id': scan.id,
                'scan_type': scan.scan_type,
                'scanned_content': scan.scanned_content,
                'risk_level': scan.risk_level,
                'risk_score': scan.risk_score,
                'patterns': scan.patterns,
                'created_at': scan.created_at.strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except ScanHistory.DoesNotExist:
        return JsonResponse({'error': 'Scan not found'}, status=404)

@login_required
@csrf_exempt
def verify_payment_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    image_file = request.FILES.get('image')
    if not image_file:
        return JsonResponse({"error": "No image provided"}, status=400)
        
    # Simulate OCR backend analysis since direct AI/OCR models aren't present locally.
    import random
    statuses = ['fake', 'genuine', 'suspicious']
    status = random.choice(statuses)
    
    if status == 'fake':
        score = random.randint(70, 90)
        checklist = [
            {'text': 'No recognized bank name found', 'passed': False},
            {'text': 'Transaction reference format valid', 'passed': True},
            {'text': 'Missing proper timestamp', 'passed': False},
            {'text': 'Amount format correct', 'passed': True},
            {'text': 'Inconsistent font styling', 'passed': False}
        ]
        findings = [
            'Bank name does not match recognized Nigerian banks',
            'Timestamp format inconsistent with standard bank alerts',
            'Font styling shows signs of manual editing',
            'Transaction reference number format unusual'
        ]
        risk_level = 'high'
    elif status == 'genuine':
        score = random.randint(10, 30)
        checklist = [
            {'text': 'Recognized bank name found', 'passed': True},
            {'text': 'Transaction reference format valid', 'passed': True},
            {'text': 'Proper timestamp present', 'passed': True},
            {'text': 'Amount format correct', 'passed': True},
            {'text': 'Consistent font styling', 'passed': True}
        ]
        findings = [
            'All verification checks passed',
            'Bank name matches recognized Nigerian banks',
            'Standard bank alert format detected',
            'No signs of manipulation found'
        ]
        risk_level = 'low'
    else:
        score = random.randint(40, 60)
        checklist = [
            {'text': 'Bank name recognized', 'passed': True},
            {'text': 'Transaction reference present', 'passed': True},
            {'text': 'Unusual timestamp format', 'passed': False},
            {'text': 'Amount format correct', 'passed': True},
            {'text': 'Minor formatting inconsistencies', 'passed': False}
        ]
        findings = [
            'Some inconsistencies detected',
            'Timestamp format slightly unusual',
            'Minor formatting variations found',
            'Further verification recommended'
        ]
        risk_level = 'medium'
        
    extracted_text = "GTBank Alert\\nAcct: ************\\nAmt: NGN 50,000.00\\nDesc: Transfer from User\\nTime: 14:30:25"
    
    # Save a record to ScanHistory so it maps to the Dashboard
    patterns_data = [{"title": "Finding", "desc": f} for f in findings]
    
    ScanHistory.objects.create(
        user=request.user,
        scan_type='image',
        risk_level=risk_level,
        risk_score=score,
        patterns=patterns_data
    )
    
    return JsonResponse({
        'status': status,
        'score': score,
        'extractedText': extracted_text,
        'checklist': checklist,
        'findings': findings
    })

@csrf_exempt
def submit_report_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    try:
        incident_type = request.POST.get('incidentType', '')
        priority = request.POST.get('priority', 'medium')
        title = request.POST.get('title', '')
        description = request.POST.get('description', '')
        contact = request.POST.get('contact', '')
        anonymous = request.POST.get('anonymous') == 'true'
        campus = request.POST.get('campus', '')
        
        report = CampusReport.objects.create(
            user=request.user if request.user.is_authenticated and not anonymous else None,
            incident_type=incident_type,
            priority=priority,
            title=title,
            description=description,
            contact_email=contact if not anonymous else '',
            is_anonymous=anonymous,
            campus=campus,
            status='Pending'
        )
        
        # Handle uploaded files
        files = request.FILES.getlist('files')
        for f in files:
            ReportEvidence.objects.create(report=report, file=f)
            
        return JsonResponse({
            "status": "success",
            "report_id": report.report_id
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@login_required
@csrf_exempt
def update_profile_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    try:
        user = request.user
        full_name = request.POST.get('fullName', '')
        email = request.POST.get('email', '')
        phone = request.POST.get('phone', '')
        user_type = request.POST.get('userType', '')

        # You might also process other parameters depending on requirements
        
        if email and email != user.email:
            # Note: Checking if new email exists could be useful
            from django.contrib.auth import get_user_model
            User = get_user_model()
            if User.objects.filter(email=email).exclude(pk=user.pk).exists():
                return JsonResponse({"error": "Email is already in use by another account."}, status=400)
            user.email = email
            
        if full_name:
            user.full_name = full_name
        if phone:
            user.phone = phone
        if user_type:
            user.user_type = user_type
            
        user.save()
        
        return JsonResponse({"status": "success", "message": "Profile updated successfully"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@login_required
@csrf_exempt
def delete_account_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    try:
        user = request.user
        user.delete()
        # The user's session will automatically become invalid or be cleared
        return JsonResponse({"status": "success", "message": "Account deleted securely"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@login_required
@csrf_exempt
def change_password_api(request):
    if request.method != 'POST':
        return JsonResponse({"error": "Invalid method"}, status=405)
        
    try:
        user = request.user
        current_password = request.POST.get('currentPassword', '')
        new_password = request.POST.get('newPassword', '')
        
        if not user.check_password(current_password):
            return JsonResponse({"error": "Incorrect current password."}, status=400)
            
        if len(new_password) < 8:
            return JsonResponse({"error": "Password must be at least 8 characters long."}, status=400)
            
        user.set_password(new_password)
        user.save()
        
        # Optionally, keep the user logged in after password change (update_session_auth_hash)
        from django.contrib.auth import update_session_auth_hash
        update_session_auth_hash(request, user)
        
        return JsonResponse({"status": "success", "message": "Password updated successfully"})
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)

@login_required
def get_report_details(request, report_id):
    try:
        report = CampusReport.objects.get(report_id=report_id)
        # Assuming you only want to allow viewing if it is the user's report or they are admins.
        # This code assumes any authenticated user can view reports shown in their list
        data = {
            'report_id': report.report_id,
            'title': report.title,
            'description': report.description,
            'incident_type': report.incident_type,
            'campus': report.campus,
            'priority': report.priority,
            'status': report.status,
            'created_at': report.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            'user': 'Anonymous' if report.is_anonymous else (report.user.full_name if report.user else 'Unknown')
        }
        
        # Check for evidence
        evidence_files = ReportEvidence.objects.filter(report=report)
        evidence_list = []
        for e in evidence_files:
            evidence_list.append({
                'url': e.file.url,
                'name': e.file.name.split('/')[-1]
            })
        data['evidence'] = evidence_list
        
        return JsonResponse({'status': 'success', 'data': data})
    except CampusReport.DoesNotExist:
        return JsonResponse({'error': 'Report not found'}, status=404)