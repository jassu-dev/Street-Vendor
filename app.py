from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///street_vendors.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    user_type = db.Column(db.String(20), nullable=False)  # 'buyer' or 'seller'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    products = db.relationship('Product', backref='seller', lazy=True)
    orders = db.relationship('Order', backref='buyer', lazy=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image_url = db.Column(db.String(200))
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    buyer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, confirmed, shipped, delivered
    delivery_address = db.Column(db.Text, nullable=False)
    payment_method = db.Column(db.String(20), default='cod')  # cod = cash on delivery
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    product = db.relationship('Product', backref='orders')

class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    product = db.relationship('Product', backref='cart_items')

class Coupon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(20), unique=True, nullable=False)
    discount_percent = db.Column(db.Integer, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='reviews')
    product = db.relationship('Product', backref='reviews')

class PasswordReset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref='password_resets')

class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')
    user1 = db.relationship('User', foreign_keys=[user1_id])
    user2 = db.relationship('User', foreign_keys=[user2_id])

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', backref='sent_messages')

# Routes
@app.route('/')
def home():
    products = Product.query.order_by(Product.created_at.desc()).limit(8).all()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user_type = request.form['user_type']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!', 'error')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            user_type=user_type
        )
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_type'] = user.user_type
            
            # Update cart count in session
            cart_count = Cart.query.filter_by(user_id=user.id).count()
            session['cart_count'] = cart_count
            
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password!', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('home'))

@app.route('/products')
def products():
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    
    query = Product.query
    
    if category:
        query = query.filter_by(category=category)
    
    if search:
        query = query.filter(Product.name.contains(search) | Product.description.contains(search))
    
    products = query.order_by(Product.created_at.desc()).all()
    categories = db.session.query(Product.category).distinct().all()
    
    return render_template('products.html', products=products, categories=categories, selected_category=category, search=search)

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product_detail.html', product=product)

@app.route('/add_product', methods=['GET', 'POST'])
def add_product():
    if 'user_id' not in session or session['user_type'] != 'seller':
        flash('You must be a seller to add products!', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        quantity = int(request.form['quantity'])
        category = request.form['category']
        image_url = request.form['image_url']
        
        product = Product(
            name=name,
            description=description,
            price=price,
            quantity=quantity,
            category=category,
            image_url=image_url,
            seller_id=session['user_id']
        )
        db.session.add(product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('my_products'))
    
    return render_template('add_product.html')

@app.route('/my_products')
def my_products():
    if 'user_id' not in session or session['user_type'] != 'seller':
        flash('You must be a seller to view your products!', 'error')
        return redirect(url_for('login'))
    
    products = Product.query.filter_by(seller_id=session['user_id']).order_by(Product.created_at.desc()).all()
    return render_template('my_products.html', products=products)

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
def edit_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        flash('You must be a seller to edit products!', 'error')
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(product_id)
    
    # Check if the product belongs to the logged-in seller
    if product.seller_id != session['user_id']:
        flash('You can only edit your own products!', 'error')
        return redirect(url_for('my_products'))
    
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        quantity = int(request.form['quantity'])
        category = request.form['category']
        image_url = request.form['image_url']
        
        # Update product
        product.name = name
        product.description = description
        product.price = price
        product.quantity = quantity
        product.category = category
        product.image_url = image_url
        
        db.session.commit()
        
        flash('Product updated successfully!', 'success')
        return redirect(url_for('my_products'))
    
    return render_template('edit_product.html', product=product)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
def delete_product(product_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        flash('You must be a seller to delete products!', 'error')
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(product_id)
    
    # Check if the product belongs to the logged-in seller
    if product.seller_id != session['user_id']:
        flash('You can only delete your own products!', 'error')
        return redirect(url_for('my_products'))
    
    # Check if product has any orders
    if product.orders:
        flash('Cannot delete product with existing orders!', 'error')
        return redirect(url_for('my_products'))
    
    # Check if product is in any carts
    if product.cart_items:
        flash('Cannot delete product that is in customers\' carts!', 'error')
        return redirect(url_for('my_products'))
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('my_products'))

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user_id' not in session:
        flash('Please login to add items to cart!', 'error')
        return redirect(url_for('login'))
    
    quantity = int(request.form['quantity'])
    product = Product.query.get_or_404(product_id)
    
    if product.quantity < quantity:
        flash('Not enough stock available!', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if item already in cart
    cart_item = Cart.query.filter_by(user_id=session['user_id'], product_id=product_id).first()
    
    if cart_item:
        cart_item.quantity += quantity
    else:
        cart_item = Cart(user_id=session['user_id'], product_id=product_id, quantity=quantity)
        db.session.add(cart_item)
    
    db.session.commit()
    
    # Update cart count in session
    cart_count = Cart.query.filter_by(user_id=session['user_id']).count()
    session['cart_count'] = cart_count
    
    flash('Item added to cart!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/cart')
def cart():
    if 'user_id' not in session:
        flash('Please login to view your cart!', 'error')
        return redirect(url_for('login'))
    
    cart_items = Cart.query.filter_by(user_id=session['user_id']).all()
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    
    # Calculate discount if coupon is applied
    discount_amount = 0
    discount_percent = 0
    applied_coupon = session.get('applied_coupon')
    
    if applied_coupon:
        discount_percent = applied_coupon['discount_percent']
        discount_amount = (subtotal * discount_percent) / 100
    
    total = subtotal - discount_amount
    
    return render_template('cart.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         total=total,
                         discount_amount=discount_amount,
                         discount_percent=discount_percent,
                         applied_coupon=applied_coupon)

@app.route('/remove_from_cart/<int:cart_id>')
def remove_from_cart(cart_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    cart_item = Cart.query.get_or_404(cart_id)
    if cart_item.user_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('cart'))
    
    db.session.delete(cart_item)
    db.session.commit()
    
    # Update cart count in session
    cart_count = Cart.query.filter_by(user_id=session['user_id']).count()
    session['cart_count'] = cart_count
    
    flash('Item removed from cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user_id' not in session:
        flash('Please login to checkout!', 'error')
        return redirect(url_for('login'))
    
    cart_items = Cart.query.filter_by(user_id=session['user_id']).all()
    
    if not cart_items:
        flash('Your cart is empty!', 'error')
        return redirect(url_for('cart'))
    
    # Get applied coupon from session
    applied_coupon = session.get('applied_coupon')
    
    if request.method == 'POST':
        delivery_address = request.form.get('delivery_address', '').strip()
        
        if not delivery_address:
            flash('Please provide a delivery address!', 'error')
            return redirect(url_for('checkout'))
        
        for cart_item in cart_items:
            if cart_item.product.quantity < cart_item.quantity:
                flash(f'Not enough stock for {cart_item.product.name}!', 'error')
                return redirect(url_for('cart'))
            
            # Calculate item total with discount
            item_total = cart_item.product.price * cart_item.quantity
            if applied_coupon:
                item_discount = (item_total * applied_coupon['discount_percent']) / 100
                item_total = item_total - item_discount
            
            # Create order
            order = Order(
                buyer_id=session['user_id'],
                product_id=cart_item.product_id,
                quantity=cart_item.quantity,
                total_price=item_total,
                delivery_address=delivery_address,
                payment_method='cod'
            )
            db.session.add(order)
            
            # Update product quantity
            cart_item.product.quantity -= cart_item.quantity
            
            # Remove from cart
            db.session.delete(cart_item)
        
        db.session.commit()
        
        # Update cart count in session (should be 0 after checkout)
        session['cart_count'] = 0
        
        # Clear applied coupon after checkout
        if 'applied_coupon' in session:
            del session['applied_coupon']
        
        flash('Order placed successfully! Cash on delivery.', 'success')
        return redirect(url_for('my_orders'))
    
    subtotal = sum(item.product.price * item.quantity for item in cart_items)
    
    # Calculate discount if coupon is applied
    discount_amount = 0
    discount_percent = 0
    applied_coupon = session.get('applied_coupon')
    
    if applied_coupon:
        discount_percent = applied_coupon['discount_percent']
        discount_amount = (subtotal * discount_percent) / 100
    
    total = subtotal - discount_amount
    
    return render_template('checkout.html', 
                         cart_items=cart_items, 
                         subtotal=subtotal,
                         total=total,
                         discount_amount=discount_amount,
                         discount_percent=discount_percent,
                         applied_coupon=applied_coupon)

@app.route('/my_orders')
def my_orders():
    if 'user_id' not in session:
        flash('Please login to view your orders!', 'error')
        return redirect(url_for('login'))
    
    if session['user_type'] == 'buyer':
        orders = Order.query.filter_by(buyer_id=session['user_id']).order_by(Order.created_at.desc()).all()
    else:  # seller
        orders = Order.query.join(Product).filter(Product.seller_id == session['user_id']).order_by(Order.created_at.desc()).all()
    
    return render_template('my_orders.html', orders=orders)

@app.route('/order/<int:order_id>')
def order_detail(order_id):
    if 'user_id' not in session:
        flash('Please login to view order details!', 'error')
        return redirect(url_for('login'))
    
    order = Order.query.get_or_404(order_id)
    
    # Check if user has permission to view this order
    if session['user_type'] == 'buyer' and order.buyer_id != session['user_id']:
        flash('You do not have permission to view this order!', 'error')
        return redirect(url_for('my_orders'))
    elif session['user_type'] == 'seller' and order.product.seller_id != session['user_id']:
        flash('You do not have permission to view this order!', 'error')
        return redirect(url_for('my_orders'))
    
    return render_template('order_detail.html', order=order)

@app.route('/update_order_status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    if 'user_id' not in session or session['user_type'] != 'seller':
        flash('Unauthorized action!', 'error')
        return redirect(url_for('my_orders'))
    
    order = Order.query.get_or_404(order_id)
    if order.product.seller_id != session['user_id']:
        flash('Unauthorized action!', 'error')
        return redirect(url_for('my_orders'))
    
    status = request.form['status']
    order.status = status
    db.session.commit()
    
    flash('Order status updated!', 'success')
    
    # Check if we're coming from order detail page
    if request.referrer and 'order/' in request.referrer:
        return redirect(url_for('order_detail', order_id=order_id))
    
    return redirect(url_for('my_orders'))

@app.route('/cancel_order/<int:order_id>', methods=['POST'])
def cancel_order(order_id):
    if 'user_id' not in session:
        flash('Please login to cancel an order!', 'error')
        return redirect(url_for('login'))
    
    order = Order.query.get_or_404(order_id)
    
    # Only the buyer can cancel their own order
    if order.buyer_id != session['user_id']:
        flash('You do not have permission to cancel this order!', 'error')
        return redirect(url_for('my_orders'))
    
    # Can only cancel if order is still pending
    if order.status != 'pending':
        flash('Cannot cancel order that has been processed!', 'error')
        return redirect(url_for('order_detail', order_id=order_id))
    
    # Update order status to cancelled
    order.status = 'cancelled'
    
    # Return the quantity to product inventory
    order.product.quantity += order.quantity
    
    db.session.commit()
    
    flash('Order cancelled successfully!', 'success')
    return redirect(url_for('order_detail', order_id=order_id))

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash('Please login to view your profile!', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash('Please login to edit your profile!', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        
        # Check if username is already taken by another user
        existing_user = User.query.filter_by(username=username).first()
        if existing_user and existing_user.id != user.id:
            flash('Username already exists!', 'error')
            return redirect(url_for('edit_profile'))
        
        # Check if email is already taken by another user
        existing_email = User.query.filter_by(email=email).first()
        if existing_email and existing_email.id != user.id:
            flash('Email already registered!', 'error')
            return redirect(url_for('edit_profile'))
        
        user.username = username
        user.email = email
        db.session.commit()
        
        session['username'] = username
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html', user=user)

# Email sending function
def send_email(to_email, subject, body):
    # This is a placeholder for actual email sending
    # In a production environment, you would use a proper email service
    # For now, we'll just print the email details and simulate success
    print(f"\nEmail would be sent to: {to_email}")
    print(f"Subject: {subject}")
    print(f"Body: {body}\n")
    
    # Uncomment and configure this section to send actual emails
    '''
    sender_email = "your-email@example.com"  # Replace with your email
    password = "your-password"  # Replace with your email password or app password
    
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = to_email
    message["Subject"] = subject
    
    message.attach(MIMEText(body, "html"))
    
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)  # Adjust for your email provider
        server.starttls()
        server.login(sender_email, password)
        server.sendmail(sender_email, to_email, message.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    '''
    
    # For development, always return success
    return True

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate a unique token
            token = secrets.token_urlsafe(32)
            
            # Set expiration time (24 hours from now)
            expires_at = datetime.utcnow() + timedelta(hours=24)
            
            # Create password reset record
            reset_record = PasswordReset(
                user_id=user.id,
                token=token,
                expires_at=expires_at
            )
            
            db.session.add(reset_record)
            db.session.commit()
            
            # Create reset link
            reset_link = url_for('reset_password', token=token, _external=True)
            
            # Email content
            subject = "Street Vendors - Password Reset"
            body = f"""
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>Hello {user.username},</p>
                <p>We received a request to reset your password. Click the link below to set a new password:</p>
                <p><a href="{reset_link}">Reset Your Password</a></p>
                <p>This link will expire in 24 hours.</p>
                <p>If you didn't request this, please ignore this email.</p>
                <p>Regards,<br>Street Vendors Team</p>
            </body>
            </html>
            """
            
            # Send email
            if send_email(user.email, subject, body):
                flash('Password reset instructions have been sent to your email.', 'success')
            else:
                flash('Error sending email. Please try again later.', 'error')
        else:
            # Don't reveal if email exists or not for security
            flash('Password reset instructions have been sent to your email if it exists in our system.', 'success')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Find the reset record
    reset_record = PasswordReset.query.filter_by(token=token, used=False).first()
    
    # Check if token exists and is not expired
    if not reset_record or reset_record.expires_at < datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return render_template('reset_password.html', token=token)
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('reset_password.html', token=token)
        
        # Update user's password
        user = User.query.get(reset_record.user_id)
        user.password_hash = generate_password_hash(password)
        
        # Mark token as used
        reset_record.used = True
        
        db.session.commit()
        
        flash('Your password has been reset successfully! Please login with your new password.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' not in session:
        flash('Please login to change your password!', 'error')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect!', 'error')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match!', 'error')
            return redirect(url_for('change_password'))
        
        if len(new_password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return redirect(url_for('change_password'))
        
        user.password_hash = generate_password_hash(new_password)
        db.session.commit()
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

@app.route('/add_review/<int:product_id>', methods=['POST'])
def add_review(product_id):
    if 'user_id' not in session:
        flash('Please login to add a review!', 'error')
        return redirect(url_for('login'))
    
    product = Product.query.get_or_404(product_id)
    rating = int(request.form['rating'])
    comment = request.form['comment']
    
    if rating < 1 or rating > 5:
        flash('Rating must be between 1 and 5!', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    if not comment.strip():
        flash('Please provide a comment!', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    # Check if user has already reviewed this product
    existing_review = Review.query.filter_by(user_id=session['user_id'], product_id=product_id).first()
    if existing_review:
        flash('You have already reviewed this product!', 'error')
        return redirect(url_for('product_detail', product_id=product_id))
    
    review = Review(
        user_id=session['user_id'],
        product_id=product_id,
        rating=rating,
        comment=comment
    )
    db.session.add(review)
    db.session.commit()
    
    flash('Review added successfully!', 'success')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/apply_coupon', methods=['POST'])
def apply_coupon():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login to apply coupon'})
    
    coupon_code = request.form.get('coupon_code', '').strip().upper()
    
    if not coupon_code:
        return jsonify({'success': False, 'message': 'Please enter a coupon code'})
    
    # Check if coupon exists and is active
    coupon = Coupon.query.filter_by(code=coupon_code, is_active=True).first()
    
    if not coupon:
        return jsonify({'success': False, 'message': 'Invalid or expired coupon code'})
    
    # Store coupon in session
    session['applied_coupon'] = {
        'code': coupon.code,
        'discount_percent': coupon.discount_percent
    }
    
    return jsonify({
        'success': True, 
        'message': f'Coupon applied! {coupon.discount_percent}% discount',
        'discount_percent': coupon.discount_percent
    })

@app.route('/remove_coupon', methods=['POST'])
def remove_coupon():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login to remove coupon'})
    
    if 'applied_coupon' in session:
        del session['applied_coupon']
    
    return jsonify({'success': True, 'message': 'Coupon removed'})

@app.route('/search')
def search():
    query = request.args.get('q', '')
    category = request.args.get('category', '')
    min_price = request.args.get('min_price', '')
    max_price = request.args.get('max_price', '')
    sort_by = request.args.get('sort_by', 'newest')
    
    products_query = Product.query
    
    if query:
        products_query = products_query.filter(
            Product.name.contains(query) | 
            Product.description.contains(query) |
            Product.category.contains(query)
        )
    
    if category:
        products_query = products_query.filter_by(category=category)
    
    if min_price:
        try:
            min_price = float(min_price)
            products_query = products_query.filter(Product.price >= min_price)
        except ValueError:
            pass
    
    if max_price:
        try:
            max_price = float(max_price)
            products_query = products_query.filter(Product.price <= max_price)
        except ValueError:
            pass
    
    # Sorting
    if sort_by == 'price_low':
        products_query = products_query.order_by(Product.price.asc())
    elif sort_by == 'price_high':
        products_query = products_query.order_by(Product.price.desc())
    elif sort_by == 'name':
        products_query = products_query.order_by(Product.name.asc())
    else:  # newest
        products_query = products_query.order_by(Product.created_at.desc())
    
    products = products_query.all()
    categories = db.session.query(Product.category).distinct().all()
    
    return render_template('search.html', 
                         products=products, 
                         categories=categories,
                         query=query,
                         selected_category=category,
                         min_price=min_price,
                         max_price=max_price,
                         sort_by=sort_by)

# Chat Routes and Socket Events
@app.route('/messages')
def messages():
    if 'user_id' not in session:
        flash('Please login to access messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user = User.query.get(user_id)
    
    # Get all conversations where the current user is involved
    conversations = Conversation.query.filter(
        ((Conversation.user1_id == user_id) | (Conversation.user2_id == user_id))
    ).order_by(Conversation.updated_at.desc()).all()
    
    # Prepare conversation data for display
    conversation_data = []
    for conv in conversations:
        # Determine the other user in the conversation
        other_user = conv.user2 if conv.user1_id == user_id else conv.user1
        
        # Get the last message
        last_message = Message.query.filter_by(conversation_id=conv.id).order_by(Message.created_at.desc()).first()
        
        # Count unread messages
        unread_count = Message.query.filter_by(
            conversation_id=conv.id,
            sender_id=other_user.id,
            is_read=False
        ).count()
        
        conversation_data.append({
            'id': conv.id,
            'other_user': other_user,
            'last_message': last_message,
            'unread_count': unread_count
        })
    
    return render_template('messages.html', conversations=conversation_data, current_user=user)

@app.route('/messages/<int:conversation_id>')
def view_conversation(conversation_id):
    if 'user_id' not in session:
        flash('Please login to access messages', 'error')
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    
    # Get the conversation
    conversation = Conversation.query.get_or_404(conversation_id)
    
    # Check if the user is part of this conversation
    if conversation.user1_id != user_id and conversation.user2_id != user_id:
        flash('You do not have permission to view this conversation', 'error')
        return redirect(url_for('messages'))
    
    # Get the other user
    other_user = conversation.user2 if conversation.user1_id == user_id else conversation.user1
    
    # Get all messages in this conversation
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.created_at.asc()).all()
    
    # Mark all unread messages as read
    unread_messages = Message.query.filter_by(
        conversation_id=conversation_id,
        sender_id=other_user.id,
        is_read=False
    ).all()
    
    for message in unread_messages:
        message.is_read = True
    
    db.session.commit()
    
    return render_template('conversation.html', 
                           conversation=conversation, 
                           messages=messages, 
                           other_user=other_user, 
                           current_user_id=user_id)

@app.route('/start_conversation/<int:user_id>', methods=['GET', 'POST'])
def start_conversation(user_id):
    if 'user_id' not in session:
        flash('Please login to send messages', 'error')
        return redirect(url_for('login'))
    
    current_user_id = session['user_id']
    
    # Check if users are different
    if current_user_id == user_id:
        flash('You cannot start a conversation with yourself', 'error')
        return redirect(url_for('messages'))
    
    # Check if the other user exists
    other_user = User.query.get_or_404(user_id)
    
    # Check if a conversation already exists between these users
    existing_conversation = Conversation.query.filter(
        ((Conversation.user1_id == current_user_id) & (Conversation.user2_id == user_id)) |
        ((Conversation.user1_id == user_id) & (Conversation.user2_id == current_user_id))
    ).first()
    
    if existing_conversation:
        return redirect(url_for('view_conversation', conversation_id=existing_conversation.id))
    
    # If POST request, create a new conversation and first message
    if request.method == 'POST':
        message_content = request.form.get('message')
        
        if not message_content:
            flash('Message cannot be empty', 'error')
            return redirect(url_for('start_conversation', user_id=user_id))
        
        # Create new conversation
        new_conversation = Conversation(user1_id=current_user_id, user2_id=user_id)
        db.session.add(new_conversation)
        db.session.flush()  # Get the ID without committing
        
        # Create first message
        new_message = Message(
            conversation_id=new_conversation.id,
            sender_id=current_user_id,
            content=message_content
        )
        db.session.add(new_message)
        db.session.commit()
        
        return redirect(url_for('view_conversation', conversation_id=new_conversation.id))
    
    return render_template('start_conversation.html', other_user=other_user)

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    if 'user_id' not in session:
        return False  # Reject the connection
    print(f"Client connected: {request.sid}")

@socketio.on('join')
def handle_join(data):
    room = data['conversation_id']
    join_room(room)
    print(f"User {session['user_id']} joined room {room}")

@socketio.on('leave')
def handle_leave(data):
    room = data['conversation_id']
    leave_room(room)
    print(f"User {session['user_id']} left room {room}")

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        return {'status': 'error', 'message': 'Not authenticated'}
    
    sender_id = session['user_id']
    conversation_id = data['conversation_id']
    message_content = data['message']
    
    # Validate the conversation exists and user is part of it
    conversation = Conversation.query.get(conversation_id)
    if not conversation:
        return {'status': 'error', 'message': 'Conversation not found'}
    
    if conversation.user1_id != sender_id and conversation.user2_id != sender_id:
        return {'status': 'error', 'message': 'Not authorized to send messages in this conversation'}
    
    # Create and save the new message
    new_message = Message(
        conversation_id=conversation_id,
        sender_id=sender_id,
        content=message_content
    )
    db.session.add(new_message)
    
    # Update conversation timestamp
    conversation.updated_at = datetime.utcnow()
    db.session.commit()
    
    # Prepare message data for the response
    message_data = {
        'id': new_message.id,
        'sender_id': sender_id,
        'content': message_content,
        'timestamp': new_message.created_at.strftime('%Y-%m-%d %H:%M:%S'),
        'is_read': False
    }
    
    # Emit the message to all users in the conversation room
    emit('new_message', message_data, room=conversation_id)
    
    return {'status': 'success', 'message': message_data}

def init_coupons():
    """Initialize default coupon codes"""
    existing_coupons = Coupon.query.all()
    if not existing_coupons:
        coupons = [
            Coupon(code='HACK200', discount_percent=20, is_active=True),
            Coupon(code='IWILLHACK30', discount_percent=30, is_active=True)
        ]
        for coupon in coupons:
            db.session.add(coupon)
        db.session.commit()
        print("Default coupon codes initialized!")

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_coupons()
    socketio.run(app,debug=False, allow_unsafe_werkzeug=True, port=1000)
