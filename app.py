import logging
from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import sqlite3
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

logging.basicConfig(level=logging.DEBUG)

@app.route('/static/<path:filename>')
def send_static(filename):
    return send_from_directory('static', filename)

def init_db():
    with sqlite3.connect('pos.db') as conn:
        c = conn.cursor()
        c.execute('''
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
        ''')
        c.execute('''
        CREATE TABLE IF NOT EXISTS Products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            category TEXT,
            image_url TEXT,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES Users(id)
        )
        ''')
        conn.commit()

class User(UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect('pos.db') as conn:
        c = conn.cursor()
        c.execute('SELECT * FROM Users WHERE id = ?', (user_id,))
        user = c.fetchone()
    if user:
        return User(id=user[0], username=user[1], password=user[2])
    return None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()
                c.execute('INSERT INTO Users (username, password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('pos.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM Users WHERE username = ?', (username,))
            user = c.fetchone()
        if user and bcrypt.check_password_hash(user[2], password):
            user_obj = User(id=user[0], username=user[1], password=user[2])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

def update_schema():
    try:
        with sqlite3.connect('pos.db') as conn:
            c = conn.cursor()
            c.execute("PRAGMA table_info(Products);")
            columns = [info[1] for info in c.fetchall()]
            if 'category' not in columns:
                c.execute('ALTER TABLE Products ADD COLUMN category TEXT')
                conn.commit()
                print("Database schema updated successfully!")
            else:
                print("Schema already up to date.")
    except Exception as e:
        print(f"An error occurred: {e}")

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        price = float(request.form['price'])
        stock = int(request.form['stock'])
        category = request.form['category']
        image_url = request.form['image_url']
        code = str(random.randint(1000, 9999))
        user_id = current_user.id
        try:
            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()
                c.execute('INSERT INTO Products (code, name, price, stock, category, image_url, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                          (code, name, price, stock, category, image_url, user_id))
                conn.commit()
            flash('Product added successfully!', 'success')
        except sqlite3.IntegrityError as e:
            logging.error(f"Error adding product: {e}")
            flash('Product code already exists. Try again.', 'danger')
        return redirect(url_for('view_products'))
    return render_template('add_product.html')

@app.route('/update_product/<int:id>', methods=['GET', 'POST'])
@login_required
def update_product(id):
    try:
        with sqlite3.connect('pos.db') as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM Products WHERE id = ?', (id,))
            product = c.fetchone()
        
        if request.method == 'POST':
            name = request.form['name']
            price = float(request.form['price'])
            stock = int(request.form['stock'])
            category = request.form['category']

            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()
                c.execute('UPDATE Products SET name = ?, price = ?, stock = ?, category = ? WHERE id = ?', 
                          (name, price, stock, category, id))
                conn.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('view_products'))
        return render_template('update_product.html', product=product)
    except Exception as e:
        logging.error("Error updating product: %s", e)
        flash("An error occurred while updating the product. Please try again.", "danger")
        return redirect(url_for('view_products'))

@app.route('/delete_product/<int:id>', methods=['POST'])
@login_required
def delete_product(id):
    try:
        with sqlite3.connect('pos.db') as conn:
            c = conn.cursor()
            c.execute('DELETE FROM Products WHERE id = ?', (id,))
            conn.commit()
        flash('Product deleted successfully!', 'success')
    except Exception as e:
        logging.error(f"Error deleting product: {e}")
        flash("An error occurred while deleting the product. Please try again.", 'danger')
    return redirect(url_for('view_products'))

@app.route('/view_products')
@login_required
def view_products():
    try:
        with sqlite3.connect('pos.db') as conn:
            c = conn.cursor()
            c.execute('SELECT id, code, name, price, stock, category, image_url FROM Products WHERE user_id = ?', (current_user.id,))
            products = c.fetchall()
        return render_template('view_products.html', products=products)
    except Exception as e:
        logging.error("Error viewing products: %s", e)
        flash("An error occurred while viewing the products. Please try again.", "danger")
        return redirect(url_for('index'))
    

@app.route('/search', methods=['GET', 'POST'])
@login_required
def search():
    categories = []
    products = []

    if request.method == 'POST':
        query = request.form.get('query', '')
        category = request.form.get('category', '')

        try:
            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()

                # Fetch categories for dropdown
                c.execute("SELECT DISTINCT category FROM Products WHERE user_id = ?", (current_user.id,))
                categories = [row[0] for row in c.fetchall()]

                # Build query based on category and search query
                if category:
                    # Filter by both query and selected category
                    c.execute("SELECT id, code, name, price, stock, category, image_url FROM Products WHERE (name LIKE ? OR code LIKE ?) AND category = ? AND user_id = ?", 
                              ('%' + query + '%', '%' + query + '%', category, current_user.id))
                else:
                    # Filter by query only if no specific category is selected
                    c.execute("SELECT id, code, name, price, stock, category, image_url FROM Products WHERE (name LIKE ? OR code LIKE ?) AND user_id = ?", 
                              ('%' + query + '%', '%' + query + '%', current_user.id))

                products = c.fetchall()
        except Exception as e:
            logging.error("Error searching for products: %s", e)
            flash("An error occurred while searching for products. Please try again.", "danger")
            return redirect(url_for('search'))

    else:
        try:
            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()
                c.execute("SELECT DISTINCT category FROM Products WHERE user_id = ?", (current_user.id,))
                categories = [row[0] for row in c.fetchall()]
        except Exception as e:
            logging.error("Error fetching categories: %s", e)
            flash("An error occurred while fetching categories. Please try again.", "danger")

    return render_template('search_products.html', products=products, categories=categories)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            with sqlite3.connect('pos.db') as conn:
                c = conn.cursor()
                c.execute('UPDATE Users SET username = ? WHERE id = ?', (username, current_user.id))
                if password:
                    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                    c.execute('UPDATE Users SET password = ? WHERE id = ?', (hashed_password, current_user.id))
                conn.commit()
            flash('Profile updated successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists.', 'danger')
    return render_template('profile.html')



if __name__ == '__main__':
    init_db()
    update_schema()
    app.run(debug=True)
