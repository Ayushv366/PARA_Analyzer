from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
import sqlite3
import os
import textstat
import random

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
DATABASE = 'users.db'

# Setup login manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin):
    def __init__(self, id_, username, password):
        self.id = id_
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id, username, password FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

# Forms
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(6, 100)])
    confirm  = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AnalyzeForm(FlaskForm):
    para = TextAreaField('Paragraph', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Analyze')

from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

tokenizer = AutoTokenizer.from_pretrained("prithivida/grammar_error_correcter_v1")
model = AutoModelForSeq2SeqLM.from_pretrained("prithivida/grammar_error_correcter_v1")

def correct_grammar(text):
    input_text = "gec: " + text
    input_ids = tokenizer.encode(input_text, return_tensors="pt", max_length=512, truncation=True)
    output_ids = model.generate(input_ids, max_length=512, num_beams=5, early_stopping=True)
    corrected_text = tokenizer.decode(output_ids[0], skip_special_tokens=True)
    return corrected_text

# DB init
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        conn.commit()
        conn.close()

def setup():
    init_db()

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (form.username.data, form.password.data))
            conn.commit()
            flash('Account created, please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already taken.', 'danger')
        finally:
            conn.close()
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username = ?", (form.username.data,))
        row = c.fetchone()
        conn.close()
        if row and row[2] == form.password.data:
            user = User(*row)
            login_user(user)
            return redirect(url_for('analyzer'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

from flask import make_response
from xhtml2pdf import pisa
from io import BytesIO
from flask import render_template_string

@app.route('/quiz', methods=['GET', 'POST'])
@login_required
def start_quiz():
    import json
    
    try:
        # If this is a POST, get the results from the form
        if request.method == 'POST':
            if 'results' not in request.form:
                flash('No analysis results found. Please analyze a paragraph first.', 'warning')
                return redirect(url_for('analyzer'))
                
            # Get the results data
            raw_data = request.form['results']
            results = json.loads(raw_data)
            
        # If this is a GET, use session data if available
        else:
            if 'last_analysis' not in session:
                flash('No analysis results found. Please analyze a paragraph first.', 'warning')
                return redirect(url_for('analyzer'))
                
            results = session['last_analysis']
        
        # Get grammar issues from results
        grammar_issues = results.get("grammar", [])
        
        # Get readability data for additional questions
        readability = {
            'reading_ease': results.get('reading_ease', 0),
            'grade_level': results.get('grade_level', 0),
            'avg_sentence_len': results.get('avg_sentence_len', 0)
        }
        
        # Create the questions
        questions = []
        
        for i, issue in enumerate(grammar_issues[:3]):  # Limit to first 3 grammar issues
            if not issue.get('suggestion'):
                continue
                
            correct = issue['suggestion'][0] if issue['suggestion'] else issue['line']
            wrong_opts = [issue['line']]
            
            if len(issue['suggestion']) > 1:
                wrong_opts.extend(issue['suggestion'][1:2])
            
            # Ensure we have unique options
            options = list(set([correct] + wrong_opts))
            
            # Add a random option if needed
            if len(options) < 3:
                random_option = f"{correct} (incorrect version)"
                options.append(random_option)
                
            # Shuffle options
            import random
            random.shuffle(options)
            
            questions.append({
                "id": f"q{i}",
                "question": f"Which is the correct version of this sentence?",
                "question_text": issue['line'],
                "options": options,
                "answer": correct,
                "explanation": issue.get('message', 'This correction improves clarity and grammar.')
            })
        
        general_questions = [
            {
                "id": f"q{len(questions)}",
                "question": "What does a high Flesch Reading Ease score indicate?",
                "question_text": "Consider the Flesch Reading Ease score in your analysis.",
                "options": [
                    "The text is difficult to read and complex",
                    "The text is easy to read and understand",
                    "The text has excessive grammar errors",
                    "The text has too many characters"
                ],
                "answer": "The text is easy to read and understand",
                "explanation": "Higher Flesch Reading Ease scores (closer to 100) indicate text that is easier to read, while lower scores (closer to 0) suggest more complex, difficult text."
            },
            {
                "id": f"q{len(questions)+1}",
                "question": "What is generally considered an ideal average sentence length for readable content?",
                "question_text": "Think about sentence length for optimal readability.",
                "options": [
                    "5-10 words",
                    "15-25 words",
                    "30-40 words",
                    "50+ words"
                ],
                "answer": "15-25 words",
                "explanation": "Sentences between 15-25 words on average tend to balance clarity with complexity. Your text has an average sentence length of " + str(readability['avg_sentence_len']) + " words."
            }
        ]
        
        questions.extend(general_questions)
        if len(questions) < 5:
            more_questions = [
                {
                    "id": f"q{len(questions)}",
                    "question": "Which of these sentences uses active voice?",
                    "question_text": "Choose the sentence that uses active voice rather than passive voice.",
                    "options": [
                        "The ball was thrown by John.",
                        "John threw the ball.",
                        "The ball had been thrown.",
                        "It was seen that the ball was thrown."
                    ],
                    "answer": "John threw the ball.",
                    "explanation": "Active voice follows the pattern Subject → Verb → Object, making writing more direct and engaging."
                },
                {
                    "id": f"q{len(questions)+1}",
                    "question": "Which is an example of a transitional phrase?",
                    "question_text": "Identify the transitional phrase that helps improve flow between sentences.",
                    "options": [
                        "Very much",
                        "Kind of",
                        "On the other hand",
                        "Really awesome"
                    ],
                    "answer": "On the other hand",
                    "explanation": "Transitional phrases like 'on the other hand', 'furthermore', and 'in conclusion' help connect ideas and improve the flow of writing."
                }
            ]
            questions.extend(more_questions[:5-len(questions)])
        
        import random
        random.shuffle(questions)
        
        session['quiz_questions'] = questions
        
        score = 0
        total = len(questions)
        
        return render_template("quiz.html", questions=questions, score=score, total=total)
        
    except json.JSONDecodeError as e:
        print(f"JSON error: {e}")
        flash('Error creating quiz: Invalid data format', 'danger')
        return redirect(url_for('analyzer'))
    except Exception as e:
        print(f"Error: {e}")
        flash(f'Error creating quiz: {str(e)}', 'danger')
        return redirect(url_for('analyzer'))

@app.route('/submit_quiz', methods=['POST'])
@login_required
def submit_quiz():
    score = 0
    total = 0
    feedback = []
    
    try:
        # Get the questions from session
        questions = session.get('quiz_questions', [])
        questions_dict = {q['id']: q for q in questions}
        
        for key in request.form:
            if key.endswith('_answer'):
                qid = key.replace('_answer', '')
                correct_answer = request.form[key]
                selected_answer = request.form.get(qid)
                
                # Skip if no answer was selected
                if not selected_answer:
                    continue
                    
                total += 1
                is_correct = selected_answer == correct_answer
                
                if is_correct:
                    score += 1
                    
                # Get the question text and explanation
                question_text = questions_dict.get(qid, {}).get('question_text', 'Question text not available')
                explanation = questions_dict.get(qid, {}).get('explanation', '')
                    
                feedback.append({
                    "question": qid,
                    "question_text": question_text,
                    "your_answer": selected_answer,
                    "correct_answer": correct_answer,
                    "correct": is_correct,
                    "explanation": explanation
                })
        
        # Make sure we have values even if the form was empty
        if total == 0:
            flash('No answers were submitted.', 'warning')
            return redirect(url_for('start_quiz'))
            
        return render_template('quiz_result.html', score=score, total=total, feedback=feedback)
        
    except Exception as e:
        print(f"Quiz submission error: {e}")
        flash(f'Error processing quiz results: {str(e)}', 'danger')
        # Pass default values to avoid template errors
        return render_template('quiz_result.html', score=0, total=0, feedback=[])

@app.route('/download_pdf', methods=['POST'])
@login_required
def download_pdf():
    from flask import request
    import json
    
    try:
        # Check if the data is present
        if 'results' not in request.form:
            flash('No results data found.', 'danger')
            return redirect(url_for('analyzer'))
            
        # Clean the data - sometimes JSON can have escape characters or formatting issues
        raw_data = request.form['results']
        # Print raw data for debugging
        print(f"Raw data: {raw_data[:100]}...")  # Print first 100 chars
        
        # Parse the JSON data
        results = json.loads(raw_data)
        
        # Convert newlines in improved text to HTML paragraphs
        if 'improved' in results:
            improved_text = results['improved'].replace('\r\n\r\n', '</p><p>').replace('\n\n', '</p><p>')
            improved_text = f"<p>{improved_text}</p>"
        else:
            improved_text = "<p>No improved text available</p>"

        # Render the template
        rendered = render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>Para Analysis Report</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
                h2 { color: #3498db; margin-top: 20px; }
                ul { padding-left: 20px; }
                li { margin-bottom: 8px; }
                .highlight { background-color: #f8f9fa; padding: 10px; border-radius: 5px; }
            </style>
        </head>
        <body>
        <h1>Para Analysis Report</h1>
        <h2>Readability</h2>
        <p>Flesch Reading Ease: {{ r.reading_ease }}</p>
        <p>Flesch-Kincaid Grade: {{ r.grade_level }}</p>
        <p>Gunning Fog Index: {{ r.fog_index }}</p>
        <ul>
        {% for tip in r.readability_tips %}
          <li>{{ tip }}</li>
        {% endfor %}
        </ul>

        <h2>Grammar Issues</h2>
        {% if r.grammar %}
        <ul>
        {% for g in r.grammar %}
          <li>{{ g.line }}: {{ g.message }} → Suggestions: {{ g.suggestion|join(', ') }}</li>
        {% endfor %}
        </ul>
        {% else %}
        <p>No grammar issues detected.</p>
        {% endif %}

        <h2>Style</h2>
        <p>Average Sentence Length: {{ r.avg_sentence_len }}</p>
        <ul>
        {% for tip in r.style_tips %}
          <li>{{ tip }}</li>
        {% endfor %}
        </ul>

        <h2>Improved Paragraph</h2>
        <div class="highlight">
          {{ improved_text|safe }}
        </div>
        </body>
        </html>
        """, r=results, improved_text=improved_text)

        # Create the PDF
        pdf = BytesIO()
        pisa.CreatePDF(BytesIO(rendered.encode('utf-8')), dest=pdf)
        pdf.seek(0)  # Go to the beginning of the file

        # Return the PDF file
        response = make_response(pdf.getvalue())
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = 'attachment; filename=analysis_report.pdf'
        return response
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Raw data: {request.form.get('results', '')}")
        flash(f'Error processing the data: Invalid JSON format. {str(e)}', 'danger')
        return redirect(url_for('analyzer'))
    except Exception as e:
        print(f"General error: {e}")
        flash(f'Error processing the data: {str(e)}', 'danger')
        return redirect(url_for('analyzer'))

@app.route('/', methods=['GET', 'POST'])
@login_required
def analyzer():
    form = AnalyzeForm()
    results = {}
    if form.validate_on_submit():
        text = form.para.data

        # Readability
        results['reading_ease'] = textstat.flesch_reading_ease(text)
        results['grade_level'] = textstat.flesch_kincaid_grade(text)
        results['fog_index'] = textstat.gunning_fog(text)
        results['readability_tips'] = [
            "Shorten long sentences.",
            "Use simpler words.",
            "Break into smaller paragraphs."
        ]

        # Grammar Correction
        corrected_text = correct_grammar(text)
        grammar = []

        original_sentences = text.split('. ')
        corrected_sentences = corrected_text.split('. ')

        for orig, corr in zip(original_sentences, corrected_sentences):
            if orig.strip() != corr.strip():
                grammar.append({
                    'line': orig.strip(),
                    'message': "Possible correction",
                    'suggestion': [corr.strip()]
                })

        # Add some mock grammar issues if none were found (for testing)
        if not grammar and len(original_sentences) > 1:
            grammar.append({
                'line': original_sentences[0].strip(),
                'message': "Consider rephrasing for clarity",
                'suggestion': [original_sentences[0].strip() + " (rephrased version)"]
            })

        results['grammar'] = grammar

        # Style
        sentences = textstat.sentence_count(text)
        words = textstat.lexicon_count(text)
        results['avg_sentence_len'] = round(words / max(sentences, 1), 2)
        results['style_tips'] = [
            "Vary sentence length.",
            "Avoid passive voice.",
        ]

        # Improved version
        results['improved'] = corrected_text
        
        # Store results in session for quiz
        session['last_analysis'] = results
        
        flash('Analysis complete. You can download the report or take a quiz.', 'success')

    return render_template('analyzer.html', form=form, results=results)

if __name__ == '__main__':
    setup()
    app.run(debug=True, host='0.0.0.0', port=5000)