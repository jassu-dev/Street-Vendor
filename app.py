from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///street_vendors.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
    return redirect(url_for('my_orders'))

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
    app.run(debug=True) 