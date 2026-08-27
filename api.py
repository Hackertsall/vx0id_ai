import flask

from flask import Flask, request, jsonify

from vx0id.core import VX0ID

from vx0id.config import Config

from vx0id.rate_limiter import RateLimiter


app = Flask(__name__)

config = Config()

vx0id = VX0ID(config)

rate_limiter = RateLimiter(config.rate_limit)


@app.route('/register_target', methods=['POST'])

@rate_limiter.limit

def register_target():

    """Register a target for scanning"""

    data = request.json

    if not data:

        return jsonify({"error": "No data provided"}), 400

        

    name = data.get('name')

    ip = data.get('ip')

    consent_ref = data.get('consent_ref')

    

    if not all([name, ip, consent_ref]):

        return jsonify({"error": "Missing required fields"}), 400

        

    target_id = vx0id.add_target(name, ip, consent_ref)

    if target_id == 0:

        return jsonify({"error": "Failed to register target"}), 400

        

    return jsonify({"target_id": target_id}), 200


@app.route('/request_scan/<int:target_id>', methods=['POST'])

@rate_limiter.limit

def request_scan(target_id):

    """Request a scan of a registered target"""

    data = request.json

    if not data:

        return jsonify({"error": "No data provided"}), 400

        

    consent_ref = data.get('consent_ref')

    if not consent_ref:

        return jsonify({"error": "Missing consent reference"}), 400

        

    results = vx0id.verify_defensive_checks(target_id, consent_ref)

    return jsonify(results), 200


@app.route('/get_audit_log', methods=['GET'])

def get_audit_log():

    """Get audit log entries"""

    # Implementation omitted for brevity

    return jsonify({"audit_log": []}), 200


@app.route('/health', methods=['GET'])

def health():

    """Health check endpoint"""

    return jsonify({"status": "healthy"}), 200


if __name__ == '__main__':

    app.run(host=config.bind_address, port=config.port)
