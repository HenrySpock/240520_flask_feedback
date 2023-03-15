from flask import Flask, render_template, redirect, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from models import db, Users, Feedback
from forms import RegistrationForm, LoginForm, FeedbackForm
from flask import session, flash
from functools import wraps
from flask import redirect, session, url_for
from flask_migrate import Migrate

app = Flask(__name__) 
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql:///usersdb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'secretkey'

db.init_app(app)
with app.app_context():
    db.create_all()
    
migrate = Migrate(app, db)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    return redirect('/register') 

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'username' in session:
        user = Users.query.filter_by(username=session['username']).first()
        feedbacks = Feedback.query.filter_by(username=session['username']).all()
        return render_template('user_profile.html', user=user, feedbacks=feedbacks)
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        new_user = Users.create_user(username, password, email, first_name, last_name)
        return redirect(f'/users/{username}')
    return render_template('register.html', form=form) 

@app.route('/login', methods=['GET', 'POST'])
def login(): 
    if 'username' in session:
        user = Users.query.filter_by(username=session['username']).first()
        feedbacks = Feedback.query.filter_by(username=session['username']).all()
        return render_template('user_profile.html', user=user, feedbacks=feedbacks)
    form = LoginForm() 
    if form.validate_on_submit(): 
        username = form.username.data
        password = form.password.data
        user = Users.authenticate(username, password)
        if user:
            session['username'] = username 
            return redirect(f'/users/{username}')
        else:
            flash('Invalid username or password.')
            return redirect('/login')
    print("Form validation failed.")
    return render_template('login.html', form=form)

@app.route('/users/<username>')
def user_profile(username):
    if 'username' in session and session['username'] == username:
        user = Users.query.filter_by(username=username).first()
        feedbacks = Feedback.query.filter_by(username=username).all()
        return render_template('user_profile.html', user=user, feedbacks=feedbacks)
    else:
        return redirect('/login')
    
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

@app.route('/users/<username>/delete', methods=['POST'])
def delete_user(username):
    if 'username' in session and session['username'] == username:
        user = Users.query.filter_by(username=username).first()
        if user:
            # Delete user's feedback
            Feedback.query.filter_by(username=username).delete()
            # Delete user
            db.session.delete(user)
            db.session.commit()
            # Clear session data
            session.pop('username', None)
            return redirect('/login')
        else:
            return "User not found", 404
    else:
        return redirect('/login') 

@app.route('/users/<username>/feedback/add', methods=['GET', 'POST'])
@login_required
def add_feedback(username):
    form = FeedbackForm()
    if 'username' in session and session['username'] == username: 
        if form.validate_on_submit():
            feedback = Feedback(username=username, title=form.title.data, content=form.content.data)
            db.session.add(feedback)
            db.session.commit()
            flash('Feedback added successfully.', 'success')
            return redirect(f'/users/{username}')
        return render_template('add_feedback.html', form=form, username=username)
    else:
        return redirect('/login')
    
@app.route('/feedback/<int:feedback_id>/edit', methods=['GET', 'POST'])
def edit_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.username:
        form = FeedbackForm(obj=feedback)
        if form.validate_on_submit():
            feedback.title = form.title.data
            feedback.content = form.content.data
            db.session.commit()
            return redirect(f'/users/{feedback.username}')
        return render_template('edit_feedback.html', form=form, feedback_id=feedback_id, feedback=feedback)
    else:
        return redirect('/login')

@app.route('/feedback/<int:feedback_id>/delete', methods=['POST'])
def delete_feedback(feedback_id):
    feedback = Feedback.query.get_or_404(feedback_id)
    if 'username' in session and session['username'] == feedback.username:
        db.session.delete(feedback)
        db.session.commit()
        return redirect(f'/users/{feedback.username}')
    else:
        return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
