from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import logging
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'supersecret'
db = SQLAlchemy(app)

# VULNERABILITY: logger writes to a local file with no rotation, no redaction,
# and no separation between "safe" application logs and sensitive data.
# Anything passed to logger.info()/logger.warning() below lands in app.log
# in plaintext exactly as supplied.
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s'
)
logger = logging.getLogger('app09')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    role = db.Column(db.String(20), default='user')
    password = db.Column(db.String(120))
    credit_card = db.Column(db.String(20))
    auth_token = db.Column(db.String(120))


with app.app_context():
    db.create_all()


# VULNERABILITY: Login failures are never logged at all.
# There is no logging.warning()/logging.info() call anywhere in this route,
# no failed-attempt counter, and no lockout after N tries. An attacker can
# brute-force this endpoint indefinitely and the app.log file will show
# absolutely nothing - not even the fact that the endpoint was hit.
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    user = User.query.filter_by(username=username).first()

    if user is None or user.password != password:
        # No audit trail whatsoever for the failed attempt.
        # No lockout, no rate limiting, no counter of any kind.
        return jsonify({'error': 'invalid credentials'}), 401

    return jsonify({'message': 'logged in', 'user_id': user.id, 'role': user.role})


# VULNERABILITY: Sensitive data logged in plaintext.
# The full password, credit card number, and auth token are written
# directly to app.log / stdout. Anyone with read access to the log file
# (or a downstream log aggregator) now has these secrets in cleartext.
@app.route('/api/checkout', methods=['POST'])
def checkout():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')
    card_number = data.get('credit_card', '')
    token = data.get('auth_token', '')

    logger.info(
        f"Checkout attempt: user={username} password={password} "
        f"card={card_number} token={token}"
    )

    return jsonify({'message': 'checkout processed'})


# VULNERABILITY: Log injection / log forging.
# The user-supplied 'action' field is concatenated straight into the log
# line with no sanitization or encoding. An attacker can embed CRLF
# (\r\n) sequences to inject fake log entries, splitting a single request
# into what looks like multiple independent, forged log lines - e.g. a
# fabricated "admin login succeeded" entry that never actually happened.
@app.route('/api/log-action', methods=['POST'])
def log_action():
    data = request.get_json(silent=True) or {}
    username = data.get('username', 'anonymous')
    action = data.get('action', '')

    # No newline stripping, no escaping, no validation - raw string
    # concatenation directly into the log sink.
    logger.info("User action: user=" + username + " action=" + action)

    return jsonify({'message': 'action logged'})


# VULNERABILITY: Sensitive admin action performed with zero audit logging.
# Deleting a user is one of the most sensitive operations an admin can
# perform, yet there is no logging call here at all - no record of who
# deleted whom, when, or from where. A compromised admin account (or an
# insider) can delete users with no trace left behind.
@app.route('/admin/delete-user/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
    # No audit log entry - compare to how this SHOULD look:
    #   logger.warning(f"AUDIT: admin={request.remote_addr} deleted user_id={user_id}")
    return jsonify({'message': 'deleted'})


# VULNERABILITY: No alerting / monitoring on repeated failures.
# This endpoint exists purely to illustrate the gap: even though failed
# login attempts (see /login above) are never logged, imagine they were -
# there is still no monitoring layer anywhere in this app that counts
# failures per source IP, no threshold-based alert, and no integration
# with a SIEM or paging system. A real brute-force campaign against
# /login from a single IP would trigger absolutely nothing here.
#
# What proper monitoring would look like (NOT implemented in this app):
#   failed_attempts_by_ip[request.remote_addr] += 1
#   if failed_attempts_by_ip[request.remote_addr] > 5:
#       send_alert_to_security_team(ip=request.remote_addr)
#       logger.critical(f"ALERT: possible brute force from {request.remote_addr}")
@app.route('/api/security-status', methods=['GET'])
def security_status():
    return jsonify({
        'monitoring_enabled': False,
        'alerting_enabled': False,
        'note': 'No alerts are generated regardless of failure volume from a single IP.'
    })


# VULNERABILITY: Mass assignment + plaintext secrets stored, used only to
# seed data for the demo attacks above.
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json(silent=True) or {}
    user = User(
        username=data.get('username'),
        email=data.get('email'),
        password=data.get('password'),
        role=data.get('role', 'user'),
        credit_card=data.get('credit_card', ''),
        auth_token=data.get('auth_token', '')
    )
    db.session.add(user)
    db.session.commit()
    return jsonify({'id': user.id, 'message': 'registered'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5009)
