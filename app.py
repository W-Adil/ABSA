# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential
import os
from dotenv import load_dotenv
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reviews.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Azure AI Configuration
AZURE_LANGUAGE_KEY = os.getenv('AZURE_LANGUAGE_KEY')
AZURE_LANGUAGE_ENDPOINT = os.getenv('AZURE_LANGUAGE_ENDPOINT')

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class ReviewAspect(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    review_id = db.Column(db.Integer, db.ForeignKey('review.id'), nullable=False)
    aspect = db.Column(db.String(100))
    sentiment = db.Column(db.String(20))
    confidence = db.Column(db.Float)
    opinions = db.Column(db.JSON)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_name = db.Column(db.String(100), nullable=False)
    review_text = db.Column(db.Text, nullable=False)
    sentiment_score = db.Column(db.Float)
    sentiment_label = db.Column(db.String(20))
    created_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    aspects = db.relationship('ReviewAspect', backref='review', lazy=True)

# Azure AI Text Analytics Client
def get_text_analytics_client():
    credential = AzureKeyCredential(AZURE_LANGUAGE_KEY)
    return TextAnalyticsClient(endpoint=AZURE_LANGUAGE_ENDPOINT, credential=credential)

# Analyze sentiment using Azure AI
def analyze_sentiment(text):
    client = get_text_analytics_client()
    try:
        response = client.analyze_sentiment(
            [text],
            show_opinion_mining=True
        )[0]
        
        sentiment_result = {
            'score': response.confidence_scores.positive,
            'label': response.sentiment,
            'aspects': []
        }
        
        for sentence in response.sentences:
            if hasattr(sentence, 'mined_opinions'):
                for opinion in sentence.mined_opinions:
                    aspect = {
                        'text': opinion.target.text,
                        'sentiment': opinion.target.sentiment,
                        'confidence': opinion.target.confidence_scores.positive,
                        'opinions': []
                    }
                    sentiment_result['aspects'].append(aspect)
                    
        return sentiment_result
    except Exception as e:
        print(f"Error analyzing sentiment: {str(e)}")
        return {'score': 0.0, 'label': 'error', 'aspects': []}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    reviews = Review.query.order_by(Review.created_date.desc()).limit(10).all()
    return render_template('index.html', reviews=reviews)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
            
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password)
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful!')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
            
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/submit-review', methods=['GET', 'POST'])
@login_required
def submit_review():
    if request.method == 'POST':
        product_name = request.form['product_name']
        review_text = request.form['review_text']
        reviews_added = 0
        
        # Process manual review if provided
        if review_text.strip():
            sentiment_result = analyze_sentiment(review_text)
            review = Review(
                product_name=product_name,
                review_text=review_text,
                sentiment_score=sentiment_result['score'],
                sentiment_label=sentiment_result['label'],
                user_id=current_user.id,
                created_date=datetime.utcnow()
            )
            db.session.add(review)
            db.session.commit()
            
            for aspect in sentiment_result['aspects']:
                review_aspect = ReviewAspect(
                    review_id=review.id,
                    aspect=aspect['text'],
                    sentiment=aspect['sentiment'],
                    confidence=aspect['confidence'],
                    opinions=aspect.get('opinions', [])
                )
                db.session.add(review_aspect)
            db.session.commit()
            reviews_added += 1

        # Process file reviews if uploaded
        if 'review_file' in request.files:
            file = request.files['review_file']
            if file and file.filename.endswith('.txt'):
                file_content = file.read().decode('utf-8')
                reviews = [r.strip() for r in file_content.split('\n\n') if r.strip()]
                
                for review_content in reviews:
                    sentiment_result = analyze_sentiment(review_content)
                    review = Review(
                        product_name=product_name,
                        review_text=review_content,
                        sentiment_score=sentiment_result['score'],
                        sentiment_label=sentiment_result['label'],
                        user_id=current_user.id,
                        created_date=datetime.utcnow()
                    )
                    db.session.add(review)
                    db.session.commit()
                    
                    for aspect in sentiment_result['aspects']:
                        review_aspect = ReviewAspect(
                            review_id=review.id,
                            aspect=aspect['text'],
                            sentiment=aspect['sentiment'],
                            confidence=aspect['confidence'],
                            opinions=aspect.get('opinions', [])
                        )
                        db.session.add(review_aspect)
                    db.session.commit()
                    reviews_added += 1

        flash(f'{reviews_added} review(s) submitted successfully!')
        return redirect(url_for('my_reviews'))
        
    return render_template('submit_review.html')

@app.route('/my-reviews')
@login_required
def my_reviews():
    reviews = Review.query.filter_by(user_id=current_user.id).order_by(Review.created_date.desc()).all()
    return render_template('my_reviews.html', reviews=reviews)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)