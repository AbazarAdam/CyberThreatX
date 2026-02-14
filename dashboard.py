"""
Flask Web Dashboard for CyberThreatX
Provides a web interface for viewing and managing threat alerts.
"""

import json
import math
from flask import Flask, render_template, request, jsonify, Response
from datetime import datetime
from pathlib import Path

import db
import sigma_loader
import auth
import config
from flask_login import login_user, logout_user, login_required, current_user
from flask import flash, redirect, url_for
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY

# Global variable for rules (in a real app, this might be in a cache or DB)
ACTIVE_RULES = []

# Database path - Use centralized config
DB_PATH = config.DB_PATH

def load_app_rules():
    """Loads Sigma rules into the dashboard memory cache.

    This function fetches rule metadata to display in the UI.
    """
    global ACTIVE_RULES
    try:
        rules_folder = config.SIGMA_RULES_DIR
        # Since we just want metadata for the dashboard, we use load_sigma_rules
        raw_rules = sigma_loader.load_sigma_rules(rules_folder)
        ACTIVE_RULES = [sigma_loader.get_rule_metadata(r) for r in raw_rules]
        logger.info(f"[*] Loaded {len(ACTIVE_RULES)} rules for dashboard")
    except Exception as e:
        logger.error(f"[!] Error loading rules for dashboard: {e}")
        ACTIVE_RULES = []

@app.route('/')
@login_required
def index():
    """Renders the dashboard home page with stats and recent alerts."""
    db.init_db(DB_PATH)
    stats = db.get_stats(DB_PATH)
    recent_alerts = db.get_alerts(limit=10, db_path=DB_PATH)
    return render_template('index.html', stats=stats, recent_alerts=recent_alerts)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = db.verify_user(username, password, DB_PATH)
        
        if user:
            user_obj = auth.User(user)
            login_user(user_obj)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout action."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/rules')
@login_required
def rules():
    """
    Page displaying all active Sigma rules.
    """
    return render_template('rules.html', rules=ACTIVE_RULES)


@app.route('/alerts')
@login_required
def alerts():
    """
    Alerts list page with filtering and pagination.
    """
    # Get filter parameters
    severity = request.args.get('severity', '')
    rule_name = request.args.get('rule_name', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    page = int(request.args.get('page', 1))
    
    # Build filters dict
    filters = {}
    if severity:
        filters['severity'] = severity
    if rule_name:
        filters['rule_name'] = rule_name
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date
    
    # Pagination settings
    per_page = 50
    offset = (page - 1) * per_page
    
    # Get alerts
    alerts_list = db.get_alerts(filters=filters, limit=per_page, offset=offset, db_path=DB_PATH)
    
    # Get total count for pagination
    total_count = db.get_alert_count(filters=filters, db_path=DB_PATH)
    total_pages = math.ceil(total_count / per_page)
    
    # Get available rules for filter dropdown
    available_rules = db.get_unique_rules(DB_PATH)
    
    return render_template(
        'alerts.html',
        alerts=alerts_list,
        filters={
            'severity': severity,
            'rule_name': rule_name,
            'start_date': start_date,
            'end_date': end_date
        },
        available_rules=available_rules,
        page=page,
        total_pages=total_pages,
        total_count=total_count
    )


@app.route('/alert/<int:alert_id>')
@login_required
def alert_detail(alert_id):
    """
    Alert detail page.
    
    Args:
        alert_id: Alert ID
    """
    # Get alert
    alert = db.get_alert_by_id(alert_id, DB_PATH)
    
    if not alert:
        return render_template('404.html'), 404
    
    # Pretty-print raw event JSON
    raw_event_json = json.dumps(alert['raw_event'], indent=2)
    
    # Parse threat intel if exists
    ti_data = []
    if alert.get('threat_intel'):
        try:
            ti_data = json.loads(alert['threat_intel'])
        except:
            pass
            
    # Get comments
    comments = db.get_alert_comments(alert_id, DB_PATH)
    
    return render_template('alert_detail.html', alert=alert, raw_event_json=raw_event_json, comments=comments, threat_intel=ti_data)

@app.route('/alert/<int:alert_id>/triage', methods=['POST'])
@login_required
def alert_triage(alert_id):
    """Update alert status or assignment."""
    status = request.form.get('status')
    assigned_to = request.form.get('assigned_to')
    comment = request.form.get('comment')
    
    if status:
        db.update_alert_status(alert_id, status, current_user.id, DB_PATH)
    
    if assigned_to:
        db.assign_alert(alert_id, int(assigned_to), current_user.id, DB_PATH)
        
    if comment:
        db.add_alert_comment(alert_id, current_user.id, comment, DB_PATH)
        
    flash('Alert updated successfully.', 'success')
    return redirect(url_for('alert_detail', alert_id=alert_id))


@app.route('/correlations')
@login_required
def correlations():
    """List all correlated alerts."""
    corrs = db.get_correlations(DB_PATH)
    return render_template('correlations.html', correlations=corrs)

@app.route('/correlation/<int:corr_id>')
@login_required
def correlation_detail(corr_id):
    """Correlation detail page."""
    corr = db.get_correlation_by_id(corr_id, DB_PATH)
    if not corr:
        return render_template('404.html'), 404
        
    # Get contributing alerts
    alert_ids = json.loads(corr['contributing_alert_ids'])
    contributing_alerts = []
    for aid in alert_ids:
        a = db.get_alert_by_id(aid, DB_PATH)
        if a:
            contributing_alerts.append(a)
            
    return render_template('correlation_detail.html', correlation=corr, alerts=contributing_alerts)

@app.route('/export/alerts')
@login_required
def export_alerts():
    """
    Export alerts as JSON based on current filters.
    """
    # Get filter parameters (same as alerts page)
    severity = request.args.get('severity', '')
    rule_name = request.args.get('rule_name', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Build filters dict
    filters = {}
    if severity:
        filters['severity'] = severity
    if rule_name:
        filters['rule_name'] = rule_name
    if start_date:
        filters['start_date'] = start_date
    if end_date:
        filters['end_date'] = end_date
    
    # Get all matching alerts (no limit)
    alerts_list = db.get_alerts(filters=filters, limit=10000, db_path=DB_PATH)
    
    # Convert to JSON
    json_data = json.dumps(alerts_list, indent=2)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'cyberthreatx_alerts_{timestamp}.json'
    
    # Return as downloadable file
    return Response(
        json_data,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/export/alert/<int:alert_id>')
@login_required
def export_alert(alert_id):
    """
    Export a single alert as JSON.
    
    Args:
        alert_id: Alert ID
    """
    # Get alert
    alert = db.get_alert_by_id(alert_id, DB_PATH)
    
    if not alert:
        return jsonify({'error': 'Alert not found'}), 404
    
    # Convert to JSON
    json_data = json.dumps(alert, indent=2)
    
    # Generate filename
    filename = f'alert_{alert_id}.json'
    
    # Return as downloadable file
    return Response(
        json_data,
        mimetype='application/json',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )


@app.route('/api/stats')
def api_stats():
    """
    API endpoint for statistics (for auto-refresh).
    """
    stats = db.get_stats(DB_PATH)
    return jsonify(stats)


@app.errorhandler(404)
def not_found(error):
    """
    404 error handler.
    """
    return render_template('404.html'), 404


def main():
    """Runs the Flask development server after initializing the environment."""
    logger.info("=" * 40)
    logger.info("🚀 CyberThreatX Web Dashboard")
    logger.info("=" * 40)
    logger.info(f"📊 Dashboard URL: http://localhost:5000")
    logger.info(f"💾 Database: {DB_PATH}")
    logger.info("=" * 40)
    
    # Initialize database
    db.init_db(DB_PATH)
    
    # Initialize Auth (after DB is ready)
    auth.init_auth(app)
    
    # Load rules
    load_app_rules()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)


if __name__ == '__main__':
    main()
