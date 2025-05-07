from flask import render_template, request, redirect, url_for, session, flash
from app.database import DatabaseConnection, hash_password, verify_password
import traceback
from flask import jsonify
from flask_login import login_required, current_user, login_user, logout_user
import logging
from app import User
from . import mail  
from flask_mail import Message
from datetime import datetime, timedelta
from random import randint
from flask_login import logout_user

# No need to import create_app here, because routes will be initialized from __init__.py
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

db = DatabaseConnection()

def init_routes(app):
    @app.route('/')
    def home():
        try:
            logger.debug("Accessing Home Route")
            query = "SELECT * FROM products LIMIT 10"
            products = db.fetch_all(query)
            
            logger.debug(f"Products Found: {len(products)}")
            
            # Detailed product logging
            for product in products:
                logger.debug(f"Product: {product}")
            
            return render_template('home.html', products=products)
        except Exception as e:
            logger.error(f"Home Route Error: {e}")
            logger.error(traceback.format_exc())
            flash(f"Error loading products: {e}", 'error')
            return render_template('home.html', products=[])

    


    @app.route('/login', methods=['GET', 'POST'])
    def login():
        # If already logged in, skip everything
        if current_user.is_authenticated:
            flash('You are already logged in', 'info')
            return redirect(url_for('home'))

        # === PHASE 2: Verify OTP ===
        # This branch only runs after we’ve sent an OTP and redirected here
        if request.method == 'POST' and session.get('otp_step'):
            entered_otp = request.form.get('otp')
            sent_time = datetime.fromisoformat(session.get('otp_time'))
            
            # Expiry check (5 minutes)
            if datetime.utcnow() - sent_time > timedelta(minutes=5):
                session.clear()
                flash('OTP expired. Please log in again.', 'error')
                return redirect(url_for('login'))

            # Match?
            if entered_otp == session.get('otp_code'):
                # Fetch user data and log in
                user_data = db.fetch_one(
                    "SELECT id, username, email FROM users WHERE id = %s",
                    (session['otp_user_id'],)
                )
                user_obj = User(user_data['id'], user_data['username'], user_data['email'])
                login_user(user_obj)
                session['user_id'] = user_data['id']
                session['username'] = user_data['username']

                # Clean up OTP session keys
                for key in ('otp_step','otp_user_id','otp_code','otp_time'):
                    session.pop(key, None)

                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid code. Please try again.', 'error')
                return render_template('verify_otp.html')

        # === PHASE 1: Username/Password ===
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            # Your existing secure lookup + rate-limiting…
            query = """
            SELECT id, username, password, email, 
                   (SELECT COUNT(*) FROM login_attempts 
                    WHERE user_id = users.id AND timestamp > NOW() - INTERVAL 1 HOUR) AS recent_attempts
            FROM users 
            WHERE username = %s
            """
            user = db.fetch_one(query, (username,))

            if user and user['recent_attempts'] >= 5:
                flash('Too many login attempts. Please try again later.', 'error')
                return render_template('login.html')

            if user and verify_password(user['password'], password):
                # ✅ Credentials OK → generate OTP
                otp = randint(100000, 999999)
                session['otp_step']    = True
                session['otp_user_id'] = user['id']
                session['otp_code']    = str(otp)
                session['otp_time']    = datetime.utcnow().isoformat()

                # Send it via Flask-Mail
                msg = Message("Your Fashion Store Login Code", recipients=[user['email']])
                msg.body = f"Hello {user['username']},\n\nYour one-time login code is: {otp}\nIt expires in 5 minutes."
                mail.send(msg)

                flash('An OTP has been sent to your email. Please enter it below.', 'info')
                return render_template('verify_otp.html')

            else:
                # Record failed attempt (as before)
                record_attempt = """
                INSERT INTO login_attempts (user_id, username, timestamp)
                VALUES ((SELECT id FROM users WHERE username = %s), %s, NOW())
                """
                db.execute_query(record_attempt, (username, username))
                flash('Invalid username or password', 'error')

        # GET request or fall-through: show login form
        return render_template('login.html')
                            
    @app.route('/logout')
    def logout():
        logout_user()         # <- clears Flask-Login's logged-in state
        session.clear()       # <- clears everything in Flask's session (like user_id, username)
        flash('You have been logged out.', 'info')
        return redirect(url_for('login'))
    @app.route('/check_username')
    def check_username():
        username = request.args.get('username')
        
        if not username:
            return jsonify({'exists': False})
        
        try:
            query = "SELECT * FROM users WHERE username = %s"
            result = db.fetch_one(query, (username,))
            return jsonify({'exists': result is not None})
        except Exception as e:
            logger.error(f"Username check failed: {e}")
            return jsonify({'exists': False})


    
    @app.route('/register', methods=['GET', 'POST'])
    def register():
        """User registration route with enhanced error handling"""
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            dob = request.form.get('dob')
            phone_number = request.form.get('phone_number')
            gender = request.form.get('gender')

            print(f"🔍 Registration Attempt: Username={username}, Email={email}, DOB={dob}, Phone={phone_number}, Gender={gender}")

            # Validate required fields
            if not username or not email or not password:
                flash('Username, Email, and Password are required.', 'error')
                return render_template('register.html')

            # Validate Date of Birth (optional, but must be valid if provided)
            if dob:
                try:
                    from datetime import datetime
                    dob_date = datetime.strptime(dob, "%Y-%m-%d")  # Ensure correct format
                except ValueError:
                    flash('Invalid Date of Birth format. Use YYYY-MM-DD.', 'error')
                    return render_template('register.html')

            # Validate Phone Number (optional, but must be numeric and max 15 chars)
            if phone_number and (not phone_number.isdigit() or len(phone_number) > 15):
                flash('Phone Number must be numeric and up to 15 digits.', 'error')
                return render_template('register.html')

            # Validate Gender (optional, but must be 'Male', 'Female', or 'Other')
            if gender and gender not in ['Male', 'Female', 'Other']:
                flash('Invalid gender selection.', 'error')
                return render_template('register.html')

            try:
                # Check if username or email already exists
                check_query = "SELECT * FROM users WHERE username = %s OR email = %s"
                existing_user = db.fetch_one(check_query, (username, email))

                if existing_user:
                    if existing_user['username'] == username:
                        flash('Username already exists.', 'error')
                    elif existing_user['email'] == email:
                        flash('Email is already registered.', 'error')
                    return render_template('register.html')

                # Hash password before storing
                hashed_password = hash_password(password)

                # Insert new user
                insert_query = """
                INSERT INTO users (username, email, password, dob, phone_number, gender) 
                VALUES (%s, %s, %s, %s, %s, %s)
                """
                success = db.execute_query(insert_query, (username, email, hashed_password, dob, phone_number, gender))

                if success:
                    flash('Registration successful! Please log in.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Registration failed. Please try again.', 'error')
                    print("❌ Failed to insert user into database.")

            except Exception as e:
                print(f"❌ Critical Registration Error: {e}")
                print(traceback.format_exc())
                flash('An unexpected error occurred during registration.', 'error')

        return render_template('register.html')



    @app.route('/product/<int:product_id>')
    def product_detail(product_id):
        """View product details including reviews and category information"""
        try:
            print(f"🟢 Received product_id: {product_id}")  # ✅ Debugging Step 1

            # ✅ Fetch product details with category info
            product_query = """
            SELECT p.id, p.name, p.description, p.price, p.stock, p.image_url, p.created_at,
                   c.Product_Type AS category_name, c.Age_Group AS age_group, c.Gender AS gender
            FROM products p
            LEFT JOIN Category c ON p.Category_ID = c.Category_ID
            WHERE p.id = %s
            """
            product = db.fetch_one(product_query, (product_id,))

            if not product:
                print(f"❌ Product ID {product_id} NOT found in database!")  # ✅ Debugging Step 2
                flash("Product not found.", "error")
                return redirect(url_for('home'))

            print(f"✅ Product Data Loaded: {product}")  # ✅ Debugging Step 3

            # ✅ Fetch product reviews
            reviews_query = """
            SELECT r.review_text, r.rating, u.username, r.created_at
            FROM product_reviews r
            JOIN users u ON r.user_id = u.id
            WHERE r.product_id = %s
            ORDER BY r.created_at DESC
            """
            reviews = db.fetch_all(reviews_query, (product_id,))

            print(f"✅ Reviews Found: {len(reviews)}")  # ✅ Debugging Step 4

            # ✅ Attach reviews to product
            product["reviews"] = reviews

            return render_template('product_detail.html', product=product)

        except Exception as e:
            print(f"❌ Error loading product details: {e}")  # ✅ Debugging Step 5
            flash(f"Error loading product details: {e}", "error")
            return redirect(url_for('home'))






    @app.route('/product/<int:product_id>/review', methods=['POST'])
    def submit_review(product_id):
        """Submit a product review"""
        if 'user_id' not in session:
            flash("You must be logged in to submit a review.", "error")
            return redirect(url_for('login'))

        try:
            rating = request.form.get('rating')
            review_text = request.form.get('content')

            # ✅ Debugging: Print form data
            print(f"📝 Received Review - Product ID: {product_id}, Rating: {rating}, Text: {review_text}")

            if not rating or not review_text:
                flash("Please provide both a rating and a review.", "error")
                return redirect(url_for('product_detail', product_id=product_id))

            # ✅ Insert review into database
            review_query = """
            INSERT INTO product_reviews (product_id, user_id, rating, review_text, created_at) 
            VALUES (%s, %s, %s, %s, NOW())
            """
            db.execute_query(review_query, (product_id, session['user_id'], rating, review_text))

            print("✅ Review inserted into database successfully!")  # ✅ Debugging

            flash("Review submitted successfully!", "success")
            return redirect(url_for('product_detail', product_id=product_id))

        except Exception as e:
            print(f"❌ Error submitting review: {e}")  # ✅ Debugging
            flash(f"Error submitting review: {e}", "error")
            return redirect(url_for('product_detail', product_id=product_id))






    @app.route('/cart')
    def view_cart():
        """View shopping cart"""
        if 'user_id' not in session:
            flash("Please login to view your cart.", "error")
            return redirect(url_for('login'))

        try:
            query = """
            SELECT c.id AS cart_item_id, p.id AS product_id, p.name, p.price, c.quantity, 
                   (p.price * c.quantity) AS total_price, p.image_url
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
            """
            cart_items = db.fetch_all(query, (session['user_id'],))

            total_cart_value = sum(item['total_price'] for item in cart_items) if cart_items else 0

            return render_template('cart.html', cart_items=cart_items, total_cart_value=total_cart_value)
        
        except Exception as e:
            flash(f"Error loading cart: {e}", "error")
            return redirect(url_for('home'))





    @app.route('/add_to_cart/<int:product_id>', methods=['POST'])
    def add_to_cart(product_id):
        """Add product to cart"""
        if 'user_id' not in session:
            flash('Please login to add items to cart', 'error')
            return redirect(url_for('login'))
        
        try:
            # Check if product exists
            product_query = "SELECT * FROM products WHERE id = %s"
            product = db.fetch_one(product_query, (product_id,))
            
            if not product:
                flash('Product not found', 'error')
                return redirect(url_for('home'))
            
            # Check if product is already in cart
            check_cart_query = """
            SELECT * FROM cart 
            WHERE user_id = %s AND product_id = %s
            """
            existing_cart_item = db.fetch_one(check_cart_query, (session['user_id'], product_id))
            
            if existing_cart_item:
                # Update quantity if product already in cart
                update_query = """
                UPDATE cart 
                SET quantity = quantity + 1 
                WHERE user_id = %s AND product_id = %s
                """
                db.execute_query(update_query, (session['user_id'], product_id))
                flash('Increased product quantity in cart', 'success')
            else:
                # Add new item to cart
                insert_query = """
                INSERT INTO cart (user_id, product_id, quantity) 
                VALUES (%s, %s, 1)
                """
                db.execute_query(insert_query, (session['user_id'], product_id))
                flash('Product added to cart', 'success')
            
            return redirect(url_for('view_cart'))
        
        except Exception as e:
            flash(f'Error adding to cart: {e}', 'error')
            return redirect(url_for('home'))
    @app.route('/remove_from_cart/<int:cart_item_id>', methods=['POST'])
    def remove_from_cart(cart_item_id):
        """Remove item from cart"""
        if 'user_id' not in session:
            flash('Please login to modify cart', 'error')
            return redirect(url_for('login'))
        
        try:
            # Verify cart item belongs to current user
            check_query = "SELECT * FROM cart WHERE id = %s AND user_id = %s"
            cart_item = db.fetch_one(check_query, (cart_item_id, session['user_id']))
            
            if not cart_item:
                flash('Cart item not found', 'error')
                return redirect(url_for('view_cart'))
            
            # Remove item from cart
            remove_query = "DELETE FROM cart WHERE id = %s"
            db.execute_query(remove_query, (cart_item_id,))
            db.connection.commit()

            flash('Item removed from cart', 'success')
            return redirect(url_for('view_cart'))
    
        except Exception as e:
            flash(f'Error removing item from cart: {e}', 'error')
            return redirect(url_for('view_cart'))


    @app.route('/wishlist')
    def view_wishlist():
        """View user's wishlist"""
        if 'user_id' not in session:
            flash("Please log in to view your wishlist.", "warning")
            return redirect(url_for('login'))

        try:
            wishlist_items = db.fetch_all("""
                SELECT w.product_id, p.name, p.description, p.price, p.image_url 
                FROM wishlist w
                JOIN products p ON w.product_id = p.id
                WHERE w.user_id = %s
            """, (session['user_id'],))

            print(f"Wishlist Items: {wishlist_items}")  # Debugging

            return render_template('wishlist.html', wishlist_items=wishlist_items)
        except Exception as e:
            print(f"Error loading wishlist: {e}")
            flash(f"Error loading wishlist: {e}", "danger")
            return redirect(url_for('home'))




    
    
       

    @app.route('/update_cart_quantity', methods=['POST'])
    def update_cart_quantity():
        """Update the quantity of an item in the cart"""
        if 'user_id' not in session:
            flash('Please login to modify your cart', 'error')
            return redirect(url_for('login'))

        try:
            cart_item_id = request.form.get('cart_item_id')
            quantity = request.form.get('quantity')

            # ✅ Ensure quantity is a valid integer
            if not cart_item_id or not quantity:
                flash('Invalid cart item update request.', 'error')
                return redirect(url_for('view_cart'))

            try:
                quantity = int(quantity)  # Convert to integer
                if quantity <= 0:
                    flash('Quantity must be at least 1.', 'error')
                    return redirect(url_for('view_cart'))
            except ValueError:
                flash('Invalid quantity value.', 'error')
                return redirect(url_for('view_cart'))

            # ✅ Check if the cart item exists
            check_query = "SELECT * FROM cart WHERE id = %s AND user_id = %s"
            cart_item = db.fetch_one(check_query, (cart_item_id, session['user_id']))

            if not cart_item:
                flash('Cart item not found.', 'error')
                return redirect(url_for('view_cart'))

            # ✅ Update cart quantity in the database
            update_query = "UPDATE cart SET quantity = %s WHERE id = %s AND user_id = %s"
            db.execute_query(update_query, (quantity, cart_item_id, session['user_id']))
            db.connection.commit()

            flash('Cart updated successfully!', 'success')
            return redirect(url_for('view_cart'))

        except Exception as e:
            flash(f"Error updating cart: {e}", "error")
            return redirect(url_for('view_cart'))


    @app.route('/checkout', methods=['GET', 'POST'])
    def checkout():
        """Checkout process with multiple payment options and item persistence"""
        if 'user_id' not in session:
            flash('Please login to proceed with checkout', 'error')
            return redirect(url_for('login'))

        try:
            # 1. Fetch cart items
            cart_query = """
            SELECT c.id, p.id AS product_id, p.name, p.price, c.quantity, 
                   p.stock, (p.price * c.quantity) AS total_price
            FROM cart c
            JOIN products p ON c.product_id = p.id
            WHERE c.user_id = %s
            """
            cart_items = db.fetch_all(cart_query, (session['user_id'],))

            if not cart_items:
                flash('Your cart is empty', 'error')
                return redirect(url_for('home'))

            total_cart_value = sum(item['total_price'] for item in cart_items)

            if request.method == 'POST':
                # 2. Gather form data
                full_name    = request.form.get('full_name')
                address      = request.form.get('address')
                phone_number = request.form.get('phone_number')
                city         = request.form.get('city')
                postal_code  = request.form.get('postal_code')
                payment_mode = request.form.get('payment_mode', 'COD')
                card_number  = request.form.get('card_number')
                upi_id       = request.form.get('upi_id')

                # 3. Validation
                if not all([full_name, address, phone_number, city, postal_code]):
                    flash('Please fill in all delivery details', 'error')
                    return render_template('checkout.html',
                                           cart_items=cart_items,
                                           total_cart_value=total_cart_value)

                if payment_mode == 'Card' and not card_number:
                    flash('Card details are required for Card payment.', 'error')
                    return render_template('checkout.html',
                                           cart_items=cart_items,
                                           total_cart_value=total_cart_value)

                if payment_mode == 'UPI' and not upi_id:
                    flash('UPI ID is required for UPI payment.', 'error')
                    return render_template('checkout.html',
                                           cart_items=cart_items,
                                           total_cart_value=total_cart_value)

                # 4. Begin transaction
                db.connection.autocommit = False
                cursor = db.connection.cursor()

                try:
                    # 5. Insert order
                    order_query = """
                    INSERT INTO orders 
                      (user_id, total_price, payment_status, full_name,
                       address, phone_number, city, postal_code, payment_mode)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """
                    cursor.execute(order_query, (
                        session['user_id'],
                        total_cart_value,
                        'Pending',       # you can change status logic later
                        full_name,
                        address,
                        phone_number,
                        city,
                        postal_code,
                        payment_mode
                    ))
                    order_id = cursor.lastrowid

                    # 6. Insert order_items and update stock
                    for item in cart_items:
                        # stock check
                        if item['quantity'] > item['stock']:
                            raise Exception(f"Insufficient stock for {item['name']}")

                        # insert into order_items
                        cursor.execute(
                            "INSERT INTO order_items (order_id, product_id, quantity, price) "
                            "VALUES (%s, %s, %s, %s)",
                            (order_id, item['product_id'], item['quantity'], item['total_price'])
                        )

                        # decrement stock
                        cursor.execute(
                            "UPDATE products SET stock = stock - %s WHERE id = %s",
                            (item['quantity'], item['product_id'])
                        )

                    # 7. Clear cart
                    cursor.execute("DELETE FROM cart WHERE user_id = %s",
                                   (session['user_id'],))

                    # 8. Commit
                    db.connection.commit()
                    flash('Order placed successfully! Thank you for your purchase.', 'success')
                    return redirect(url_for('order_confirmation', order_id=order_id))

                except Exception as order_error:
                    db.connection.rollback()
                    flash(f'Order processing failed: {order_error}', 'error')
                    return render_template('checkout.html',
                                           cart_items=cart_items,
                                           total_cart_value=total_cart_value)

                finally:
                    db.connection.autocommit = True

            # GET: render checkout form
            return render_template('checkout.html',
                                   cart_items=cart_items,
                                   total_cart_value=total_cart_value)

        except Exception as e:
            flash(f'Checkout error: {e}', 'error')
            return redirect(url_for('view_cart'))


    @app.route('/order_confirmation/<int:order_id>')
    def order_confirmation(order_id):
        
        """Order confirmation page"""
        if 'user_id' not in session:
            flash('Please login to view order details', 'error')
            return redirect(url_for('login'))
        
        try:
            # Fetch order details
            order_query = """
            SELECT o.*, u.username 
            FROM orders o
            JOIN users u ON o.user_id = u.id
            WHERE o.id = %s AND o.user_id = %s
            """
            order = db.fetch_one(order_query, (order_id, session['user_id']))
            
            if not order:
                flash('Order not found', 'error')
                return redirect(url_for('home'))
            
            # Fetch order items
            order_items_query = """
            SELECT oi.*, p.name as product_name 
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = %s
            """
            order_items = db.fetch_all(order_items_query, (order_id,))
            
            return render_template('order_confirmation.html', 
                                   order=order, 
                                   order_items=order_items)
        
        except Exception as e:
            flash(f'Error retrieving order details: {e}', 'error')
            return redirect(url_for('home'))
    @app.route('/profile', methods=['GET', 'POST'])
    def user_profile():
        """User profile management route"""
        if 'user_id' not in session:
            flash('Please login to view profile', 'error')
            return redirect(url_for('login'))

        try:
            # Fetch current user details
            query = "SELECT id, username, email, dob, phone_number, gender FROM users WHERE id = %s"
            user = db.fetch_one(query, (session['user_id'],))

            if request.method == 'POST':
                # Get form data
                new_email = request.form.get('email')
                dob = request.form.get('dob')
                phone_number = request.form.get('phone_number')
                gender = request.form.get('gender')
                current_password = request.form.get('current_password')
                new_password = request.form.get('new_password')
                confirm_password = request.form.get('confirm_password')

                # Check if password update is requested
                if current_password:
                    # Verify current password
                    verify_query = "SELECT password FROM users WHERE id = %s"
                    stored_user = db.fetch_one(verify_query, (session['user_id'],))

                    if not verify_password(stored_user['password'], current_password):
                        flash('Current password is incorrect', 'error')
                        return render_template('profile.html', user=user)

                    # Validate new password
                    if new_password:
                        if new_password != confirm_password:
                            flash('New passwords do not match', 'error')
                            return render_template('profile.html', user=user)

                        # Hash new password
                        hashed_new_password = hash_password(new_password)

                        # Update user details including password
                        update_query = """
                        UPDATE users 
                        SET email = %s, password = %s, dob = %s, phone_number = %s, gender = %s
                        WHERE id = %s
                        """
                        success = db.execute_query(update_query, (new_email, hashed_new_password, dob, phone_number, gender, session['user_id']))
                    else:
                        flash('New password field is empty', 'error')
                        return render_template('profile.html', user=user)
                else:
                    # Update profile details excluding password
                    update_query = """
                    UPDATE users 
                    SET email = %s, dob = %s, phone_number = %s, gender = %s
                    WHERE id = %s
                    """
                    success = db.execute_query(update_query, (new_email, dob, phone_number, gender, session['user_id']))

                if success:
                    flash('Profile updated successfully', 'success')
                    return redirect(url_for('user_profile'))
                else:
                    flash('Failed to update profile', 'error')

            return render_template('profile.html', user=user)

        except Exception as e:
            flash(f'Error accessing profile: {e}', 'error')
            return redirect(url_for('home'))

    @app.route('/search', methods=['GET'])
    def search_products():
        """Advanced product search with multiple filters, including category"""
        try:
            query = request.args.get('query', '').strip()
            category = request.args.get('category', '')
            gender = request.args.get('gender', '')
            age_group = request.args.get('age_group', '')
            min_price = request.args.get('min_price', type=float)
            max_price = request.args.get('max_price', type=float)
            sort_by = request.args.get('sort_by', 'relevance')

            # Debugging Statements
            print(f"Search Query Entered: {query}")
            print(f"Filters: Category={category}, Gender={gender}, Age Group={age_group}, Min Price={min_price}, Max Price={max_price}")

            # Build SQL query
            search_query = """
            SELECT p.*, 
                   c.Product_Type AS category_name, c.Age_Group AS age_group, c.Gender AS gender,
                   AVG(pr.rating) as average_rating, 
                   COUNT(pr.id) as review_count
            FROM products p
            LEFT JOIN product_reviews pr ON p.id = pr.product_id
            LEFT JOIN Category c ON p.Category_ID = c.Category_ID
            WHERE 1=1
            """
            params = []

            # Add search keyword condition
            if query:
                search_query += " AND (p.name LIKE %s OR p.description LIKE %s)"
                params.extend([f'%{query}%', f'%{query}%'])

            # Add category filter
            if category:
                search_query += " AND c.Product_Type = %s"
                params.append(category)

            # Add gender filter
            if gender:
                search_query += " AND c.Gender = %s"
                params.append(gender)

            # Add age group filter
            if age_group:
                search_query += " AND c.Age_Group = %s"
                params.append(age_group)

            # Add price filters
            if min_price is not None:
                search_query += " AND p.price >= %s"
                params.append(min_price)

            if max_price is not None:
                search_query += " AND p.price <= %s"
                params.append(max_price)

            search_query += " GROUP BY p.id"

            # Sorting
            if sort_by == 'price_asc':
                search_query += " ORDER BY p.price ASC"
            elif sort_by == 'price_desc':
                search_query += " ORDER BY p.price DESC"
            elif sort_by == 'rating':
                search_query += " ORDER BY average_rating DESC"
            else:
                search_query += " ORDER BY p.id DESC"

            # Debug SQL Query
            print(f"Final SQL Query: {search_query}")
            print(f"SQL Parameters: {params}")

            # Execute query
            products = db.fetch_all(search_query, params)

            # Debug Results
            print(f"Products Found in DB: {len(products)}")
            for p in products:
                print(f"Product: {p['name']} - ${p['price']}")

            # ✅ Fetch distinct categories for dropdown
            category_query = "SELECT DISTINCT Product_Type FROM Category"
            categories = db.fetch_all(category_query)

            return render_template('search_results.html', 
                                   products=products, 
                                   categories=categories,
                                   query_params=request.args)
        except Exception as e:
            print(f"Search Error: {e}")
            flash(f'Search error: {e}', 'error')
            return redirect(url_for('home'))


    @app.route('/add_to_wishlist/<int:product_id>', methods=['POST'])
    def add_to_wishlist(product_id):
        """Add product to wishlist"""
        if 'user_id' not in session:
            flash('Please login to add items to wishlist', 'error')
            return redirect(url_for('login'))
        
        try:
            # Check if product exists
            product_query = "SELECT * FROM products WHERE id = %s"
            product = db.fetch_one(product_query, (product_id,))
            
            if not product:
                flash('Product not found', 'error')
                return redirect(url_for('home'))
            
            # Check if product is already in wishlist
            check_wishlist_query = """
            SELECT * FROM wishlist 
            WHERE user_id = %s AND product_id = %s
            """
            existing_wishlist_item = db.fetch_one(check_wishlist_query, (session['user_id'], product_id))
            
            if existing_wishlist_item:
                flash('Product already in wishlist', 'info')
            else:
                # Add new item to wishlist
                insert_query = """
                INSERT INTO wishlist (user_id, product_id) 
                VALUES (%s, %s)
                """
                db.execute_query(insert_query, (session['user_id'], product_id))
                flash('Product added to wishlist', 'success')
            
            return redirect(request.referrer or url_for('home'))
        
        except Exception as e:
            flash(f'Error adding to wishlist: {e}', 'error')
            return redirect(url_for('home'))

    


    @app.route('/remove_from_wishlist/<int:product_id>', methods=['POST'])
    def remove_from_wishlist(product_id):
        """Remove item from wishlist"""
        if 'user_id' not in session:
            flash('Please login to modify your wishlist', 'error')
            return redirect(url_for('login'))
        
        try:
            user_id = session['user_id']
            print(f"User ID: {user_id}, Product ID: {product_id}")  # ✅ Debugging

            # ✅ Verify the wishlist item belongs to the current user
            check_query = """
            SELECT * FROM wishlist 
            WHERE product_id = %s AND user_id = %s
            """
            wishlist_item = db.fetch_one(check_query, (product_id, user_id))

            print(f"Wishlist Item Found: {wishlist_item}")  # ✅ Debugging

            if not wishlist_item:
                flash('Wishlist item not found', 'error')
                return redirect(url_for('view_wishlist'))
            
            # ✅ Remove item from wishlist
            remove_query = """
            DELETE FROM wishlist 
            WHERE product_id = %s AND user_id = %s
            """
            db.execute_query(remove_query, (product_id, user_id))
            db.connection.commit()  # ✅ Ensure changes are saved

            flash('Item removed from wishlist', 'success')
            return redirect(url_for('view_wishlist'))

        except Exception as e:
            print(f"Error removing item from wishlist: {e}")
            flash(f'Error removing item from wishlist: {e}', 'error')
            return redirect(url_for('view_wishlist'))






    @app.route('/recommendations')
    def product_recommendations():
        """Generate product recommendations"""
        if 'user_id' not in session:
            flash('Please login to see personalized recommendations', 'error')
            return redirect(url_for('login'))
        
        try:
            # 1. Recommendations based on previous purchases
            purchase_recommendation_query = """
            SELECT DISTINCT p.* 
            FROM products p
            JOIN order_items oi ON p.id = oi.product_id
            JOIN orders o ON oi.order_id = o.id
            WHERE o.user_id IN (
                SELECT DISTINCT o2.user_id 
                FROM orders o2
                JOIN order_items oi2 ON o2.id = oi2.order_id
                WHERE oi2.product_id IN (
                    SELECT DISTINCT product_id 
                    FROM order_items 
                    WHERE order_id IN (
                        SELECT id 
                        FROM orders 
                        WHERE user_id = %s
                    )
                )
            )
            AND p.id NOT IN (
                SELECT DISTINCT product_id 
                FROM order_items 
                WHERE order_id IN (
                    SELECT id 
                    FROM orders 
                    WHERE user_id = %s
                )
            )
            LIMIT 10
            """
            
            # 2. Recommendations based on wishlist
            wishlist_recommendation_query = """
            SELECT p.* 
            FROM products p
            JOIN wishlist w ON p.id = w.product_id
            WHERE w.user_id IN (
                SELECT user_id 
                FROM wishlist 
                WHERE product_id IN (
                    SELECT product_id 
                    FROM wishlist 
                    WHERE user_id = %s
                )
            )
            AND p.id NOT IN (
                SELECT product_id 
                FROM wishlist 
                WHERE user_id = %s
            )
            LIMIT 10
            """
            
            # 3. Recommendations based on top-rated products
            top_rated_query = """
            SELECT p.*, AVG(pr.rating) as avg_rating
            FROM products p
            JOIN product_reviews pr ON p.id = pr.product_id
            GROUP BY p.id
            ORDER BY avg_rating DESC
            LIMIT 10
            """
            
            # Fetch recommendations
            purchase_recommendations = db.fetch_all(purchase_recommendation_query, (session['user_id'], session['user_id']))
            wishlist_recommendations = db.fetch_all(wishlist_recommendation_query, (session['user_id'], session['user_id']))
            top_rated_recommendations = db.fetch_all(top_rated_query)
            
            return render_template('recommendations.html', 
                                   purchase_recommendations=purchase_recommendations,
                                   wishlist_recommendations=wishlist_recommendations,
                                   top_rated_recommendations=top_rated_recommendations)
        
        except Exception as e:
            flash(f'Error generating recommendations: {e}', 'error')
            return redirect(url_for('home'))
    @app.route('/dashboard')
    @login_required
    def user_dashboard():
        # Get user info from current_user (Flask-Login) and session
        user_id = current_user.id
        
        # Use SQLAlchemy-style query here for demonstration
        # This would need to be adapted to your custom DB connection
        recent_orders_query = """
        SELECT * FROM orders 
        WHERE user_id = %s 
        ORDER BY created_at DESC 
        LIMIT 5
        """
        recent_orders = db.fetch_all(recent_orders_query, (user_id,))
        
        # Calculate total spent
        total_spent_query = """
        SELECT SUM(total_price) as total FROM orders WHERE user_id = %s
        """
        total_spent_result = db.fetch_one(total_spent_query, (user_id,))
        total_spent = total_spent_result['total'] if total_spent_result and total_spent_result['total'] else 0
        
        return render_template('dashboard.html', 
                               orders=recent_orders, 
                               total_spent=total_spent)

    @app.route('/account-settings', methods=['GET', 'POST'])
    @login_required
    def account_settings():
        user_id = current_user.id
        
        if request.method == 'POST':
            # Update user profile
            full_name = request.form.get('full_name')
            phone_number = request.form.get('phone_number')
            address = request.form.get('address')
            
            update_query = """
            UPDATE users 
            SET full_name = %s, phone_number = %s, address = %s
            WHERE id = %s
            """
            
            db.execute_query(update_query, (full_name, phone_number, address, user_id))
            
            # Handle profile picture upload if you have the functionality
            if 'profile_picture' in request.files:
                file = request.files['profile_picture']
                if file and file.filename:
                    # Implement file saving logic here
                    pass
            
            flash('Account updated successfully!', 'success')
            return redirect(url_for('account_settings'))
        
        # Get current user data
        user_query = """
        SELECT * FROM users WHERE id = %s
        """
        user_data = db.fetch_one(user_query, (user_id,))
        
        return render_template('account_settings.html', user=user_data)
    @app.route('/my-orders')
    def my_orders():
        if 'user_id' not in session:
            flash('Please login to view your orders', 'error')
            return redirect(url_for('login'))

        try:
            orders_query = """
            SELECT id, total_price, payment_status, payment_mode, full_name, city, created_at
            FROM orders
            WHERE user_id = %s
            ORDER BY created_at DESC
            """
            orders = db.fetch_all(orders_query, (session['user_id'],))
            return render_template('my_orders.html', orders=orders)
        except Exception as e:
            flash(f'Failed to load your orders: {e}', 'error')
            return redirect(url_for('home'))
    @app.route('/order/<int:order_id>', endpoint='order_details')
    def view_order(order_id):
        # ✅ now Flask will resolve it as 'order_details'

        if 'user_id' not in session:
            flash('Please login to view order details', 'error')
            return redirect(url_for('login'))

        try:
            order_query = """
            SELECT * FROM orders
            WHERE id = %s AND user_id = %s
            """
            order = db.fetch_one(order_query, (order_id, session['user_id']))
            if not order:
                flash("Order not found", "error")
                return redirect(url_for('my_orders'))

            items_query = """
            SELECT oi.*, p.name AS product_name
            FROM order_items oi
            JOIN products p ON oi.product_id = p.id
            WHERE oi.order_id = %s
            """
            order_items = db.fetch_all(items_query, (order_id,))

            return render_template('order_details.html', order=order, order_items=order_items)
        except Exception as e:
            flash(f"Failed to load order details: {e}", "error")
            return redirect(url_for('my_orders'))


