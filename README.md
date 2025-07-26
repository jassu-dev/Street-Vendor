# Street Vendors - Raw Materials Ecommerce Platform

A beautiful and modern ecommerce website built with Flask, designed specifically for street vendors to buy and sell raw materials, building supplies, and tools. This platform connects local vendors with buyers in a user-friendly marketplace.

## 🌟 Features

### For Buyers
- **Browse Products**: Search and filter through a wide range of raw materials
- **Advanced Search**: Search by keywords, category, price range, and sort options
- **Product Reviews**: Read and write reviews with star ratings
- **Shopping Cart**: Add items to cart and manage quantities
- **Secure Checkout**: Complete purchases with a streamlined checkout process
- **Order Tracking**: View order history and track delivery status
- **User Profile**: Manage account information and view purchase history
- **Profile Management**: Edit profile information and change password

### For Sellers
- **Product Management**: Add, edit, and manage product listings
- **Inventory Control**: Track stock levels and update quantities
- **Order Management**: Process incoming orders and update status
- **Sales Analytics**: View product performance and sales statistics
- **Seller Dashboard**: Comprehensive overview of business metrics

### General Features
- **User Authentication**: Secure login and registration system
- **Profile Management**: Edit profile information and change passwords
- **Product Reviews**: Star-based rating system with user comments
- **Advanced Search**: Multi-criteria search with filters and sorting
- **Responsive Design**: Beautiful UI that works on all devices
- **Real-time Updates**: Live inventory and order status updates
- **Modern UI**: Clean, professional design with Bootstrap 5

## 🛠️ Technology Stack

- **Backend**: Flask (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML5, CSS3, JavaScript
- **UI Framework**: Bootstrap 5
- **Icons**: Font Awesome 6
- **Authentication**: Flask-SQLAlchemy with password hashing

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd street-vendors
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the website**
   Open your browser and go to `http://localhost:5000`

## 📖 Usage Guide

### Getting Started

1. **Register an Account**
   - Visit the homepage and click "Register"
   - Choose whether you want to be a buyer or seller
   - Fill in your details and create your account

2. **For Buyers**
   - Browse products by category or search for specific items
   - Add items to your cart
   - Complete the checkout process
   - Track your orders in "My Orders"

3. **For Sellers**
   - Add your first product using the "Add Product" form
   - Manage your inventory and product listings
   - Process incoming orders and update status
   - View sales analytics in your profile

### Key Features Explained

#### Product Categories
- **Tools**: Hand tools, power tools, and equipment
- **Building Materials**: Lumber, concrete, bricks, etc.
- **Finishing Materials**: Paint, tiles, flooring, decorative items
- **Electrical**: Wires, switches, fixtures, components
- **Plumbing**: Pipes, fittings, fixtures
- **Hardware**: Nails, screws, fasteners
- **Safety Equipment**: Protective gear and safety items

#### Order Status Flow
1. **Pending**: Order placed, waiting for seller confirmation
2. **Confirmed**: Seller has confirmed the order
3. **Shipped**: Order has been shipped/delivered
4. **Delivered**: Order completed successfully

## 🗄️ Database Schema

The application uses SQLite with the following main tables:

- **Users**: User accounts with buyer/seller roles
- **Products**: Product listings with details and inventory
- **Orders**: Purchase orders with status tracking
- **Cart**: Shopping cart items for users
- **Reviews**: Product reviews with ratings and comments

## 🎨 Customization

### Styling
The application uses Bootstrap 5 with custom CSS. You can modify the styles in:
- `templates/base.html` - Main styling and layout
- Individual template files for page-specific styles

### Adding Features
- **Payment Integration**: Integrate with Stripe, PayPal, or other payment processors
- **Image Upload**: Add file upload functionality for product images
- **Email Notifications**: Send order confirmations and updates
- **Admin Panel**: Create an admin interface for platform management

## 🔒 Security Features

- Password hashing using Werkzeug
- Session-based authentication
- SQL injection protection with SQLAlchemy
- Input validation and sanitization
- CSRF protection (can be enhanced)

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production Deployment
For production deployment, consider:
- Using a production WSGI server (Gunicorn, uWSGI)
- Setting up a proper database (PostgreSQL, MySQL)
- Configuring environment variables
- Setting up HTTPS with SSL certificates
- Using a reverse proxy (Nginx)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🆘 Support

If you encounter any issues or have questions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## 🎯 Future Enhancements

- [x] Product reviews and ratings
- [x] Advanced search filters
- [x] Profile management
- [x] Password change functionality
- [ ] Payment gateway integration
- [ ] Real-time chat between buyers and sellers
- [ ] Mobile app development
- [ ] Multi-language support
- [ ] Advanced analytics dashboard
- [ ] Bulk order processing
- [ ] Automated inventory management
- [ ] Integration with shipping providers

---

**Built with ❤️ for the street vendor community** 