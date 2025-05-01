from flask import Flask, render_template, request, redirect, session
from flask_wtf.csrf import CSRFProtect

import csv
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'
csrf = CSRFProtect(app)
OPTIONS_FILE = 'options.txt'
VOTE_FILE = 'votes.csv'
STATUS_FILE = 'status.txt'
TITLE_FILE = 'title.txt'
CONFIG_FILE = 'vote_config.txt'

def get_vote_status():
    if not os.path.exists(STATUS_FILE):
        with open(STATUS_FILE, 'w', encoding='utf-8') as f:
            f.write('closed|hide')
    with open(STATUS_FILE, 'r', encoding='utf-8') as f:
        vote, result = f.read().strip().split('|')
        return {'vote': vote, 'result': result}

def set_vote_status(vote_status, result_status):
    with open(STATUS_FILE, 'w', encoding='utf-8') as f:
        f.write(f"{vote_status}|{result_status}")

def get_title():
    if not os.path.exists(TITLE_FILE):
        with open(TITLE_FILE, 'w', encoding='utf-8') as f:
            f.write("你更喜欢哪种编程语言？")
    with open(TITLE_FILE, 'r', encoding='utf-8') as f:
        return f.read().strip()

def set_title(title):
    with open(TITLE_FILE, 'w', encoding='utf-8') as f:
        f.write(title.strip())

def load_options():
    if not os.path.exists(OPTIONS_FILE):
        with open(OPTIONS_FILE, 'w', encoding='utf-8') as f:
            f.write("\n".join(['Python', 'JavaScript', 'C++', 'Java']))
    with open(OPTIONS_FILE, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f if line.strip()]

def get_vote_config():
    config = {'max_votes': 1, 'session_id': 'default'}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('max_votes='):
                    config['max_votes'] = int(line.strip().split('=')[1])
                elif line.startswith('session_id='):
                    config['session_id'] = line.strip().split('=')[1]
    return config

def set_vote_config(max_votes, session_id):
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"max_votes={max_votes}\nsession_id={session_id}\n")

def clear_votes():
    with open(VOTE_FILE, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['option'])

OPTIONS = load_options()

@app.route('/')
def index():
    if 'votes_cast' not in session:
        session['votes_cast'] = 0
    config = get_vote_config()
    if session.get('session_id') != config['session_id']:
        session['votes_cast'] = 0
        session['session_id'] = config['session_id']
    vote_status = get_vote_status()
    return render_template(
        'vote.html',
        options=OPTIONS,
        vote_open=(vote_status['vote'] == 'open'),
        votes_left=config['max_votes'] - session['votes_cast'],
        title=get_title()
    )

@app.route('/vote', methods=['POST'])
def vote():
    status = get_vote_status()
    config = get_vote_config()
    if status['vote'] != 'open':
        return "投票未开放", 403
    if session.get('votes_cast', 0) >= config['max_votes']:
        return "你已经投完所有票数。", 403
    selected = request.form.get('option')
    if selected in OPTIONS:
        with open(VOTE_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([selected])
        session['votes_cast'] = session.get('votes_cast', 0) + 1
    return redirect('/results')

@app.route('/results')
def results():
    status = get_vote_status()
    if status['result'] != 'show' and not session.get('admin_logged_in'):
        return "结果未开放查看", 403
    counts = {opt: 0 for opt in OPTIONS}
    with open(VOTE_FILE, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            if row[0] in counts:
                counts[row[0]] += 1
    return render_template('results.html', results=counts)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        if request.form.get('password') == 'admin123':
            session['admin_logged_in'] = True
            return redirect('/admin/options')
        return "密码错误", 403
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect('/')

@app.route('/admin/options', methods=['GET', 'POST'])
def admin_options():
    if not session.get('admin_logged_in'):
        return redirect('/admin/login')
    if request.method == 'POST':
        new_title = request.form.get('title')
        new_options = request.form.get('options')
        vote_status = request.form.get('vote_status')
        result_status = request.form.get('result_status')
        max_votes = int(request.form.get('max_votes'))
        session_id = request.form.get('session_id')

        with open(OPTIONS_FILE, 'w', encoding='utf-8') as f:
            for line in new_options.strip().split('\n'):
                f.write(line.strip() + '\n')
        set_title(new_title)
        set_vote_status(vote_status, result_status)
        set_vote_config(max_votes, session_id)

        if vote_status == 'open':
            clear_votes()  # 清空旧票

        global OPTIONS
        OPTIONS = load_options()
        return redirect('/admin/options')

    vote_status = get_vote_status()
    config = get_vote_config()
    return render_template('admin_options.html',
                           options_text='\n'.join(OPTIONS),
                           vote_status=vote_status['vote'],
                           result_status=vote_status['result'],
                           title=get_title(),
                           max_votes=config['max_votes'],
                           session_id=config['session_id'])

if __name__ == '__main__':
    app.run(debug=True)
