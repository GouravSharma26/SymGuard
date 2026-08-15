import os
import sys
import json
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from flask import Flask, request, jsonify, render_template

# Add parent directory to path so we can import analyzer
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from analyzer import Analyzer, findings_to_json

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=4)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze():
    # Handle both JSON and Multipart Form requests
    if request.is_json:
        data = request.get_json(silent=True) or {}
        code = data.get('code', '') if isinstance(data, dict) else ''
        filename = data.get('filename', 'app.py') if isinstance(data, dict) else 'app.py'
    else:
        if 'file' in request.files:
            file = request.files['file']
            code = file.read().decode('utf-8', errors='replace')
            filename = file.filename or 'app.py'
        else:
            code = request.form.get('code', '')
            filename = request.form.get('filename', 'app.py')

    if not code:
        return jsonify({"error": "No code provided"}), 400

    def run_analysis():
        analyzer = Analyzer(filename)
        findings = analyzer.analyze_source(code)
        return findings_to_json(filename, findings)

    try:
        future = executor.submit(run_analysis)
        result_json = future.result(timeout=10)
        return jsonify(result_json)
    except TimeoutError:
        return jsonify({"error": "Analysis timed out (10 seconds)"}), 408
    except SyntaxError as e:
        return jsonify({"error": f"SyntaxError in code: {e}"}), 400
    except Exception as e:
        return jsonify({"error": f"Analysis failed: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=False, use_reloader=True, port=5000)
