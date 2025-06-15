version: '3.8'
services:
  backend:
    build: ./server
    ports:
      - '5000:5000'
    environment:
      - MONGO_URI=mongodb://mongo:27017/innr-crcl
      - STRIPE_SECRET_KEY=your_stripe_secret_key
      - STRIPE_WEBHOOK_SECRET=your_webhook_secret
      - CLOUDINARY_CLOUD_NAME=your_cloud_name
      - CLOUDINARY_API_KEY=your_cloudinary_api_key
      - CLOUDINARY_API_SECRET=your_cloudinary_api_secret
      - EMAIL_USER=your_email@example.com
      - EMAIL_PASS=your_email_password
      - TWILIO_ACCOUNT_SID=your_twilio_sid
      - TWILIO_AUTH_TOKEN=your_twilio_token
      - TWILIO_PHONE=your_twilio_phone
    depends_on:
      - mongo

  frontend:
    build: ./client
    ports:
      - '3000:3000'
    environment:
      - REACT_APP_API_URL=http://localhost:5000/api
    stdin_open: true
    tty: true

  mongo:
    image: mongo
    ports:
      - '27017:27017'
    volumes:
      - mongo-data:/data/db

volumes:
  mongo-data:
# Backend Dockerfile
FROM node:18

WORKDIR /app

COPY package.json ./
COPY package-lock.json ./

RUN npm install

COPY . .

EXPOSE 5000

CMD ["node", "server.js"]
# Frontend Dockerfile
FROM node:18

WORKDIR /app

COPY package.json ./
COPY package-lock.json ./

RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
node_modules
build
.env
docker-compose up --build
const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const authRoute = require('./routes/auth');
const userRoute = require('./routes/user');
const productRoute = require('./routes/product');
const cartRoute = require('./routes/cart');
const orderRoute = require('./routes/order');
const stripeRoute = require('./routes/stripe');
const webhookRoute = require('./routes/webhook');
const uploadRoute = require('./routes/upload');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB Connected'))
    .catch(err => console.error(err));

// API Routes
app.use('/api/auth', authRoute);
app.use('/api/users', userRoute);
app.use('/api/products', productRoute);
app.use('/api/carts', cartRoute);
app.use('/api/orders', orderRoute);
app.use('/api/checkout', stripeRoute);
app.use('/api/webhook', webhookRoute);
app.use('/
server/
├── config/                # Stripe, Email, Cloudinary configs
├── controllers/           # Handles logic
├── middleware/            # Auth and role protection
├── models/                # Mongoose schemas
├── routes/                # API endpoints
├── utils/                 # Webhooks, Shippo, Email/SMS helpers
├── server.js
├── package.json
└── Dockerfile
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    role: { type: String, enum: ['viewer', 'editor', 'superadmin'], default: 'viewer' }
}, { timestamps: true });

module.exports = mongoose.model('User', UserSchema);
const mongoose = require('mongoose');

const ProductSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    price: { type: Number, required: true },
    images: [{ url: String, position: Number }],
    category: { type: String },
    stock: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.model('Product', ProductSchema);
const mongoose = require('mongoose');

const OrderSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    products: [
        { productId: String, quantity: Number }
    ],
    total: { type: Number, required: true },
    status: { type: String, default: 'pending' },
    shippingInfo: { type: Object },
    trackingNumber: { type: String },
}, { timestamps: true });

module.exports = mongoose.model('Order', OrderSchema);
const mongoose = require('mongoose');

const CartSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    products: [
        { productId: String, quantity: Number }
    ]
}, { timestamps: true });

module.exports = mongoose.model('Cart', CartSchema);
const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.token;
    if (authHeader) {
        jwt.verify(authHeader.split(" ")[1], process.env.JWT_SECRET, (err, user) => {
            if (err) return res.status(403).json("Token is not valid!");
            req.user = user;
            next();
        });
    } else {
        return res.status(401).json("You are not authenticated!");
    }
};

const verifyTokenAndAuthorization = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.id === req.params.id || req.user.isAdmin) {
            next();
        } else {
            res.status(403).json("You are not allowed to do that!");
        }
    });
};

const verifyTokenAndAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.isAdmin) {
            next();
        } else {
            res.status(403).json("Admin access required!");
        }
    });
};

module.exports = { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin };
const router = require('express').Router();
const User = require('../models/User');
const CryptoJS = require('crypto-js');
const jwt = require('jsonwebtoken');

// Register
router.post('/register', async (req, res) => {
    const newUser = new User({
        name: req.body.name,
        email: req.body.email,
        password: CryptoJS.AES.encrypt(req.body.password, process.env.JWT_SECRET).toString(),
    });
    try {
        const savedUser = await newUser.save();
        res.status(201).json(savedUser);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) return res.status(401).json("Wrong credentials!");

        const decryptedPass = CryptoJS.AES.decrypt(user.password, process.env.JWT_SECRET).toString(CryptoJS.enc.Utf8);
        if (decryptedPass !== req.body.password) return res.status(401).json("Wrong credentials!");

        const accessToken = jwt.sign({ id: user._id, isAdmin: user.isAdmin, role: user.role }, process.env.JWT_SECRET, { expiresIn: "3d" });

        const { password, ...userInfo } = user._doc;
        res.status(200).json({ ...userInfo, accessToken });
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;
const router = require('express').Router();
const Product = require('../models/Product');
const { verifyTokenAndAdmin } = require('../middleware/verifyToken');

// Create Product
router.post('/', verifyTokenAndAdmin, async (req, res) => {
    const newProduct = new Product(req.body);
    try {
        const savedProduct = await newProduct.save();
        res.status(201).json(savedProduct);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get All Products with Pagination and Filtering
router.get('/', async (req, res) => {
    const { page = 1, limit = 10, search = '', category } = req.query;
    try {
        const query = {};
        if (search) query.name = { $regex: search, $options: 'i' };
        if (category) query.category = category;

        const products = await Product.find(query)
            .limit(limit * 1)
            .skip((page - 1) * limit);
        const count = await Product.countDocuments(query);

        res.status(200).json({
            products,
            totalPages: Math.ceil(count / limit),
            currentPage: parseInt(page),
        });
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get Single Product
router.get('/:id', async (req, res) => {
    try {
        const product = await Product.findById(req.params.id);
        res.status(200).json(product);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Update Product
router.put('/:id', verifyTokenAndAdmin, async (req, res) => {
    try {
        const updatedProduct = await Product.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
        res.status(200).json(updatedProduct);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Delete Product
router.delete('/:id', verifyTokenAndAdmin, async (req, res) => {
    try {
        await Product.findByIdAndDelete(req.params.id);
        res.status(200).json('Product deleted.');
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;
const router = require('express').Router();
const Cart = require('../models/Cart');
const { verifyToken, verifyTokenAndAuthorization } = require('../middleware/verifyToken');

// Create Cart
router.post('/', verifyToken, async (req, res) => {
    const newCart = new Cart(req.body);
    try {
        const savedCart = await newCart.save();
        res.status(201).json(savedCart);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get User Cart
router.get('/:userId', verifyTokenAndAuthorization, async (req, res) => {
    try {
        const cart = await Cart.findOne({ userId: req.params.userId });
        res.status(200).json(cart);
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;
const router = require('express').Router();
const Order = require('../models/Order');
const { verifyToken, verifyTokenAndAuthorization, verifyTokenAndAdmin } = require('../middleware/verifyToken');

// Create Order
router.post('/', verifyToken, async (req, res) => {
    const newOrder = new Order(req.body);
    try {
        const savedOrder = await newOrder.save();
        res.status(201).json(savedOrder);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Get User Orders
router.get('/user/:userId', verifyTokenAndAuthorization, async (req, res) => {
    try {
        const orders = await Order.find({ userId: req.params.userId });
        res.status(200).json(orders);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Admin: Get All Orders
router.get('/', verifyTokenAndAdmin, async (req, res) => {
    try {
        const orders = await Order.find();
        res.status(200).json(orders);
    } catch (err) {
        res.status(500).json(err);
    }
});

// Update Order Status
router.put('/:id', verifyTokenAndAdmin, async (req, res) => {
    try {
        const updatedOrder = await Order.findByIdAndUpdate(req.params.id, { $set: req.body }, { new: true });
        res.status(200).json(updatedOrder);
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;
const router = require('express').Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

// Create Stripe Checkout Session
router.post('/create-checkout-session', async (req, res) => {
    try {
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            line_items: req.body.products.map(item => ({
                price_data: {
                    currency: 'usd',
                    product_data: { name: item.name },
                    unit_amount: item.price * 100,
                },
                quantity: item.quantity,
            })),
            mode: 'payment',
            success_url: `${req.body.success_url}?session_id={CHECKOUT_SESSION_ID}`,
            cancel_url: `${req.body.cancel_url}`,
        });

        res.json({ id: session.id });
    } catch (err) {
        res.status(500).json(err);
    }
});

module.exports = router;
const router = require('express').Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Order = require('../models/Order');

router.post('/', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];

    let event;

    try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        return res.status(400).send(`Webhook error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        // You would typically map session metadata to order creation here
        // For example, send an email or save the order
    }

    res.json({ received: true });
});

module.exports = router;
const router = require('express').Router();
const cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

router.post('/', async (req, res) => {
    try {
        const fileStr = req.body.data;
        const uploadedResponse = await cloudinary.uploader.upload(fileStr, { folder: 'innr-crcl' });
        res.json({ url: uploadedResponse.secure_url });
    } catch (err) {
        res.status(500).json({ error: 'Image upload failed' });
    }
});

module.exports = router;
const nodemailer = require('nodemailer');

const sendEmail = async (to, subject, text) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
        from: `"INNR CRCL" <${process.env.EMAIL_USER}>`,
        to,
        subject,
        text,
    });
};

module.exports = sendEmail;
const twilio = require('twilio');

const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);

const sendSMS = async (to, message) => {
    await client.messages.create({
        body: message,
        from: process.env.TWILIO_PHONE,
        to,
    });
};

module.exports = sendSMS;
/src
 ├── api
 ├── components
 ├── pages
 ├── redux
 └── App.js
import axios from 'axios';

const BASE_URL = 'http://localhost:5000/api';

export const publicRequest = axios.create({ baseURL: BASE_URL });

export const userRequest = (token) => 
    axios.create({
        baseURL: BASE_URL,
        headers: { token: `Bearer ${token}` },
    });
import { createSlice } from '@reduxjs/toolkit';

const userSlice = createSlice({
    name: 'user',
    initialState: { currentUser: null, isFetching: false, error: false },
    reducers: {
        loginStart: (state) => { state.isFetching = true; },
        loginSuccess: (state, action) => {
            state.isFetching = false;
            state.currentUser = action.payload;
        },
        loginFailure: (state) => {
            state.isFetching = false;
            state.error = true;
        },
        logout: (state) => {
            state.currentUser = null;
        },
    },
});

export const { loginStart, loginSuccess, loginFailure, logout } = userSlice.actions;
export default userSlice.reducer;
import { configureStore } from '@reduxjs/toolkit';
import userReducer from './userSlice';

export default configureStore({
    reducer: { user: userReducer },
});
import { publicRequest } from './axios';
import { loginStart, loginSuccess, loginFailure } from '../redux/userSlice';

export const login = async (dispatch, user) => {
    dispatch(loginStart());
    try {
        const res = await publicRequest.post('/auth/login', user);
        dispatch(loginSuccess(res.data));
    } catch (err) {
        dispatch(loginFailure());
    }
};

export const register = async (user) => {
    try {
        await publicRequest.post('/auth/register', user);
    } catch (err) {
        console.log(err);
    }
};
import React, { useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { login } from '../api/authRequest';
import { useNavigate } from 'react-router-dom';

const Login = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const dispatch = useDispatch();
    const { isFetching, error } = useSelector((state) => state.user);
    const navigate = useNavigate();

    const handleLogin = (e) => {
        e.preventDefault();
        login(dispatch, { email, password });
        navigate('/');
    };

    return (
        <div className="auth-container">
            <h2>Login</h2>
            <form onSubmit={handleLogin}>
                <input type="email" placeholder="Email" onChange={(e) => setEmail(e.target.value)} required />
                <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} required />
                <button type="submit" disabled={isFetching}>Login</button>
                {error && <span className="error">Something went wrong!</span>}
            </form>
        </div>
    );
};

export default Login;
import React, { useState } from 'react';
import { register } from '../api/authRequest';
import { useNavigate } from 'react-router-dom';

const Register = () => {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const navigate = useNavigate();

    const handleRegister = async (e) => {
        e.preventDefault();
        await register({ name, email, password });
        navigate('/login');
    };

    return (
        <div className="auth-container">
            <h2>Register</h2>
            <form onSubmit={handleRegister}>
                <input type="text" placeholder="Name" onChange={(e) => setName(e.target.value)} required />
                <input type="email" placeholder="Email" onChange={(e) => setEmail(e.target.value)} required />
                <input type="password" placeholder="Password" onChange={(e) => setPassword(e.target.value)} required />
                <button type="submit">Register</button>
            </form>
        </div>
    );
};

export default Register;
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useSelector } from 'react-redux';

import Login from './pages/Login';
import Register from './pages/Register';
import Home from './pages/Home'; // placeholder
import Dashboard from './pages/Dashboard'; // placeholder

const App = () => {
    const user = useSelector((state) => state.user.currentUser);

    return (
        <Router>
            <Routes>
                <Route path="/login" element={!user ? <Login /> : <Navigate to="/" />} />
                <Route path="/register" element={!user ? <Register /> : <Navigate to="/" />} />
                <Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/login" />} />
                <Route path="/" element={<Home />} />
            </Routes>
        </Router>
    );
};

export default App;
<Route path="/dashboard" element={user ? <Dashboard /> : <Navigate to="/login" />} />
import React, { useEffect, useState } from 'react';
import { publicRequest } from '../api/axios';
import { Link } from 'react-router-dom';

const ProductList = () => {
    const [products, setProducts] = useState([]);

    useEffect(() => {
        const fetchProducts = async () => {
            try {
                const res = await publicRequest.get('/products');
                setProducts(res.data);
            } catch (err) {
                console.log(err);
            }
        };
        fetchProducts();
    }, []);

    return (
        <div className="product-list">
            <h2>Our Products</h2>
            <div className="product-grid">
                {products.map(product => (
                    <div className="product-card" key={product._id}>
                        <Link to={`/product/${product._id}`}>
                            <img src={product.images[0]} alt={product.title} />
                            <h3>{product.title}</h3>
                            <p>${product.price}</p>
                        </Link>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default ProductList;
import React, { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { publicRequest } from '../api/axios';
import { useDispatch } from 'react-redux';
import { addProduct } from '../redux/cartSlice';

const ProductDetails = () => {
    const { id } = useParams();
    const [product, setProduct] = useState({});
    const dispatch = useDispatch();

    useEffect(() => {
        const fetchProduct = async () => {
            try {
                const res = await publicRequest.get(`/products/${id}`);
                setProduct(res.data);
            } catch (err) {
                console.log(err);
            }
        };
        fetchProduct();
    }, [id]);

    const handleAddToCart = () => {
        dispatch(addProduct({ ...product, quantity: 1 }));
    };

    return (
        <div className="product-details">
            <img src={product.images && product.images[0]} alt={product.title} />
            <div>
                <h2>{product.title}</h2>
                <p>{product.description}</p>
                <p>${product.price}</p>
                <button onClick={handleAddToCart}>Add to Cart</button>
            </div>
        </div>
    );
};

export default ProductDetails;
import { createSlice } from '@reduxjs/toolkit';

const cartSlice = createSlice({
    name: 'cart',
    initialState: { products: [], quantity: 0, total: 0 },
    reducers: {
        addProduct: (state, action) => {
            state.quantity += 1;
            state.products.push(action.payload);
            state.total += action.payload.price * action.payload.quantity;
        },
        clearCart: (state) => {
            state.products = [];
            state.quantity = 0;
            state.total = 0;
        },
    },
});

export const { addProduct, clearCart } = cartSlice.actions;
export default cartSlice.reducer;
import { configureStore } from '@reduxjs/toolkit';
import userReducer from './userSlice';
import cartReducer from './cartSlice';

export default configureStore({
    reducer: {
        user: userReducer,
        cart: cartReducer,
    },
});
import React from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { Link } from 'react-router-dom';
import { clearCart } from '../redux/cartSlice';

const Cart = () => {
    const cart = useSelector(state => state.cart);
    const dispatch = useDispatch();

    return (
        <div className="cart-page">
            <h2>Your Cart</h2>
            {cart.products.length === 0 ? (
                <p>Your cart is empty</p>
            ) : (
                <>
                    <div className="cart-items">
                        {cart.products.map((item, index) => (
                            <div className="cart-item" key={index}>
                                <img src={item.images[0]} alt={item.title} />
                                <div>
                                    <h3>{item.title}</h3>
                                    <p>${item.price} x {item.quantity}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                    <h3>Total: ${cart.total.toFixed(2)}</h3>
                    <Link to="/checkout"><button>Proceed to Checkout</button></Link>
                    <button onClick={() => dispatch(clearCart())}>Clear Cart</button>
                </>
            )}
        </div>
    );
};

export default Cart;
import React, { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { publicRequest } from '../api/axios';
import { clearCart } from '../redux/cartSlice';
import { useNavigate } from 'react-router-dom';

const Checkout = () => {
    const cart = useSelector(state => state.cart);
    const user = useSelector(state => state.user.currentUser);
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const [email, setEmail] = useState('');

    const handleCheckout = async () => {
        try {
            const res = await publicRequest.post('/checkout/payment', {
                cart,
                userEmail: user ? user.email : email,
            });
            window.location.href = res.data.url; // Stripe redirect
        } catch (err) {
            console.log(err);
        }
    };

    return (
        <div className="checkout-page">
            <h2>Checkout</h2>
            <h3>Total: ${cart.total.toFixed(2)}</h3>

            {!user && (
                <input
                    type="email"
                    placeholder="Enter your email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                />
            )}

            <button onClick={handleCheckout}>Pay with Stripe</button>
        </div>
    );
};

export default Checkout;
import React, { useEffect, useState } from 'react';
import { userRequest } from '../api/axios';
import { useSelector } from 'react-redux';
import { Link } from 'react-router-dom';

const AdminDashboard = () => {
    const [products, setProducts] = useState([]);
    const user = useSelector((state) => state.user.currentUser);

    useEffect(() => {
        const fetchProducts = async () => {
            try {
                const res = await userRequest(user.accessToken).get('/products');
                setProducts(res.data);
            } catch (err) {
                console.log(err);
            }
        };
        fetchProducts();
    }, [user]);

    const handleDelete = async (id) => {
        try {
            await userRequest(user.accessToken).delete(`/products/${id}`);
            setProducts(products.filter((item) => item._id !== id));
        } catch (err) {
            console.log(err);
        }
    };

    return (
        <div className="admin-dashboard">
            <h2>Admin Dashboard</h2>
            <Link to="/admin/create"><button>Add New Product</button></Link>
            <div className="admin-products">
                {products.map(product => (
                    <div className="admin-product" key={product._id}>
                        <img src={product.images[0]} alt={product.title} />
                        <h3>{product.title}</h3>
                        <div>
                            <Link to={`/admin/edit/${product._id}`}><button>Edit</button></Link>
                            <button onClick={() => handleDelete(product._id)}>Delete</button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default AdminDashboard;
<Route path="/admin" element={user && user.isAdmin ? <AdminDashboard /> : <Navigate to="/login" />} />
import React, { useState } from 'react';
import { userRequest } from '../api/axios';
import { useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const AdminCreateProduct = () => {
    const [title, setTitle] = useState('');
    const [description, setDescription] = useState('');
    const [price, setPrice] = useState('');
    const [images, setImages] = useState([]);
    const user = useSelector((state) => state.user.currentUser);
    const navigate = useNavigate();

    const handleImageUpload = async (e) => {
        const files = Array.from(e.target.files);
        const uploadedImages = [];

        for (let file of files) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('upload_preset', 'your_cloudinary_preset');

            const res = await axios.post('https://api.cloudinary.com/v1_1/your_cloud_name/image/upload', formData);
            uploadedImages.push(res.data.secure_url);
        }

        setImages([...images, ...uploadedImages]);
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await userRequest(user.accessToken).post('/products', { title, description, price, images });
            navigate('/admin');
        } catch (err) {
            console.log(err);
        }
    };

    return (
        <div className="admin-create">
            <h2>Create New Product</h2>
            <form onSubmit={handleSubmit}>
                <input type="text" placeholder="Product Title" value={title} onChange={(e) => setTitle(e.target.value)} required />
                <textarea placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} required />
                <input type="number" placeholder="Price" value={price} onChange={(e) => setPrice(e.target.value)
import React, { useEffect, useState } from 'react';
import { userRequest } from '../api/axios';
import { useSelector } from 'react-redux';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';

const AdminEditProduct = () => {
    const { id } = useParams();
    const [product, setProduct] = useState(null);
    const user = useSelector((state) => state.user.currentUser);
    const navigate = useNavigate();

    useEffect(() => {
        const fetchProduct = async () => {
            try {
                const res = await userRequest(user.accessToken).get(`/products/${id}`);
                setProduct(res.data);
            } catch (err) {
                console.log(err);
            }
        };
        fetchProduct();
    }, [id, user.accessToken]);

    const handleImageUpload = async (e) => {
        const files = Array.from(e.target.files);
        const uploadedImages = [];

        for (let file of files) {
            const formData = new FormData();
            formData.append('file', file);
            formData.append('upload_preset', 'your_cloudinary_preset');

            const res = await axios.post('https://api.cloudinary.com/v1_1/your_cloud_name/image/upload', formData);
            uploadedImages.push(res.data.secure_url);
        }

        setProduct({ ...product, images: [...product.images, ...uploadedImages] });
    };

    const handleImageDelete = (index) => {
        const updatedImages = [...product.images];
        updatedImages.splice(index, 1);
        setProduct({ ...product, images: updatedImages });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            await userRequest(user.accessToken).put(`/products/${id}`, product);
            navigate('/admin');
        } catch (err) {
            console.log(err);
        }
    };

    if (!product) return <p>Loading...</p>;

    return (
        <div className="admin-edit">
            <h2>Edit Product</h2>
            <form onSubmit={handleSubmit}>
                <input type="text" value={product.title} onChange={(e) => setProduct({ ...product, title: e.target.value })} required />
                <textarea value={product.description} onChange={(e) => setProduct({ ...product, description: e.target.value })} required />
                <input type="number" value={product.price} onChange={(e) => setProduct({ ...product, price: e.target.value })} required />
                <input type="file" multiple onChange={handleImageUpload} />
                <div className="image-preview">
                    {product.images.map((img, idx) => (
                        <div key={idx}>
                            <img src={img} alt="Preview" />
                            <button type="button" onClick={() => handleImageDelete(idx)}>Remove</button>
                        </div>
                    ))}
                </div>
                <button type="submit">Save Changes</button>
            </form>
        </div>
    );
};

export default AdminEditProduct;
import React, { useEffect, useState } from 'react';
import { userRequest } from '../api/axios';
import { useSelector } from 'react-redux';

const AdminOrders = () => {
    const [orders, setOrders] = useState([]);
    const user = useSelector((state) => state.user.currentUser);

    useEffect(() => {
        const fetchOrders = async () => {
            try {
                const res = await userRequest(user.accessToken).get('/orders');
                setOrders(res.data);
            } catch (err) {
                console.log(err);
            }
        };
        fetchOrders();
    }, [user.accessToken]);

    const handleStatusUpdate = async (orderId, status) => {
        try {
            await userRequest(user.accessToken).put(`/orders/${orderId}`, { status });
            setOrders(orders.map(order => order._id === orderId ? { ...order, status } : order));
        } catch (err) {
            console.log(err);
        }
    };

    return (
        <div className="admin-orders">
            <h2>Order Management</h2>
            {orders.map(order => (
                <div key={order._id} className="order-card">
                    <p><strong>Order ID:</strong> {order._id}</p>
                    <p><strong>Email:</strong> {order.userEmail}</p>
                    <p><strong>Status:</strong> {order.status}</p>
                    <div>
                        <button onClick={() => handleStatusUpdate(order._id, 'Processing')}>Processing</button>
                        <button onClick={() => handleStatusUpdate(order._id, 'Shipped')}>Shipped</button>
                        <button onClick={() => handleStatusUpdate(order._id, 'Delivered')}>Delivered</button>
                    </div>
                </div>
            ))}
        </div>
    );
};

export default AdminOrders;
const router = require('express').Router();
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const Order = require('../models/Order');

router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    let event;
    try {
        event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.log(`Webhook error: ${err.message}`);
        return res.status(400).send(`Webhook error: ${err.message}`);
    }

    if (event.type === 'checkout.session.completed') {
        const session = event.data.object;

        const newOrder = new Order({
            userEmail: session.customer_email,
            products: session.metadata.products ? JSON.parse(session.metadata.products) : [],
            amount: session.amount_total / 100,
            status: 'Pending',
        });

        try {
            await newOrder.save();
            console.log('Order created from webhook');
        } catch (err) {
            console.log(err);
        }
    }

    res.json({ received: true });
});

module.exports = router;
app.use('/api/stripe', require('./routes/stripe'));
const nodemailer = require('nodemailer');

const sendOrderConfirmation = async (email, order) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: 'Order Confirmation - INNR CRCL',
        html: `
            <h2>Thank you for your order!</h2>
            <p>Order ID: ${order._id}</p>
            <p>Total: $${order.amount}</p>
            <p>Status: ${order.status}</p>
        `,
    };

    await transporter.sendMail(mailOptions);
};

module.exports = { sendOrderConfirmation };
const { sendOrderConfirmation } = require('../utils/email');

// After saving the order:
await sendOrderConfirmation(session.customer_email, newOrder);
const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const client = twilio(accountSid, authToken);

const sendOrderSMS = async (phoneNumber, orderId, status) => {
    await client.messages.create({
        body: `Your order ${orderId} is now ${status}. Thank you for shopping with INNR CRCL!`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: phoneNumber,
    });
};

module.exports = { sendOrderSMS };
const { sendOrderSMS } = require('../utils/sms');

// After updating the order status:
await sendOrderSMS(order.userPhone, order._id, status);
const shippo = require('shippo')(process.env.SHIPPO_API_KEY);

const createShippingLabel = async (order) => {
    const addressFrom = {
        name: 'INNR CRCL',
        street1: 'Your warehouse address',
        city: 'Your city',
        state: 'Your state',
        zip: 'Your zip',
        country: 'US',
        phone: 'Your phone number',
        email: 'your@email.com',
    };

    const addressTo = {
        name: order.userName,
        street1: order.shippingAddress,
        city: order.shippingCity,
        state: order.shippingState,
        zip: order.shippingZip,
        country: 'US',
        phone: order.userPhone,
        email: order.userEmail,
    };

    const parcel = {
        length: '10',
        width: '7',
        height: '4',
        distance_unit: 'in',
        weight: '2',
        mass_unit: 'lb',
    };

    const shipment = await shippo.shipment.create({
        address_from: addressFrom,
        address_to: addressTo,
        parcels: [parcel],
        async: false,
    });

    const rate = shipment.rates[0]; // Select the first rate or apply logic to choose best

    const transaction = await shippo.transaction.create({
        rate: rate.object_id,
        label_file_type: 'PDF',
    });

    return transaction.label_url; // Return shipping label link
};

module.exports = { createShippingLabel };
const { createShippingLabel } = require('../utils/shippo');

// When status set to 'Shipped'
const labelUrl = await createShippingLabel(order);
order.shippingLabel = labelUrl;
await order.save();
version: '3.8'

services:
  backend:
    build: ./backend
    ports:
      - "5000:5000"
    environment:
      - MONGO_URL=mongodb://mongo:27017/innrcrcl
      - STRIPE_SECRET_KEY=your_stripe_key
      - STRIPE_WEBHOOK_SECRET=your_webhook_secret
      - EMAIL_USER=youremail@gmail.com
      - EMAIL_PASS=yourpassword
      - TWILIO_ACCOUNT_SID=your_twilio_sid
      - TWILIO_AUTH_TOKEN=your_twilio_token
      - TWILIO_PHONE_NUMBER=+1xxxxxxxxxx
      - SHIPPO_API_KEY=your_shippo_key
    depends_on:
      - mongo

  frontend:
    build: ./frontend
    ports:
      - "3000:80"

  mongo:
    image: mongo
    ports:
      - "27017:27017"

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
    depends_on:
      - frontend
      - backend
events { worker_connections 1024; }

http {
    server {
        listen 80;

        location /api/ {
            proxy_pass http://backend:5000/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }

        location / {
            proxy_pass http://frontend:80/;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }
}
FROM node:16

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5000

CMD ["node", "server.js"]
FROM node:16 as build

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
PORT=5000
MONGO_URL=mongodb://mongo:27017/innrcrcl

# Stripe
STRIPE_SECRET_KEY=sk_test_your_key
STRIPE_WEBHOOK_SECRET=whsec_your_webhook_secret

# Email
EMAIL_USER=youremail@gmail.com
EMAIL_PASS=your_email_password

# Twilio
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_PHONE_NUMBER=+1xxxxxxxxxx

# Shippo
SHIPPO_API_KEY=your_shippo_key

# JWT
JWT_SECRET=your_jwt_secret
REACT_APP_API_URL=http://your_domain.com/api
REACT_APP_STRIPE_PUBLIC_KEY=pk_test_your_key
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location /api/ {
        proxy_pass http://backend:5000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location / {
        proxy_pass http://frontend:80/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
certbot:
    image: certbot/certbot
    volumes:
      - ./nginx/certbot/www:/var/www/certbot
      - ./nginx/certbot/conf:/etc/letsencrypt
    entrypoint: /bin/sh -c "trap exit TERM; while :; do sleep 6h & wait $${!}; certbot renew --webroot -w /var/www/certbot; done"
docker run --rm -v $(pwd)/nginx/certbot/www:/var/www/certbot -v $(pwd)/nginx/certbot/conf:/etc/letsencrypt certbot/certbot certonly --webroot --webroot-path=/var/www/certbot --email youremail@domain.com --agree-tos --no-eff-email -d yourdomain.com -d www.yourdomain.com
ssh root@your_server_ip
apt update
apt install docker.io docker-compose -y
git clone your-repo-url
cd your-project
docker-compose up -d --build
docker-compose restart nginx
services:
  mongo:
    image: mongo
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

volumes:
  mongo_data:
certbot:
  image: certbot/certbot
  volumes:
    - ./nginx/certbot/www:/var/www/certbot
    - ./nginx/certbot/conf:/etc/letsencrypt
  entrypoint: /bin/sh -c "trap exit TERM; while :; do sleep 6h & wait $${!}; certbot renew --webroot -w /var/www/certbot --quiet --no-self-upgrade && nginx -s reload; done"
apt update
apt install nodejs npm -y
npm install -g pm2
pm2 start server.js --name innrcrcl
pm2 startup
pm2 save
{
  "secure_url": "https://res.cloudinary.com/your-cloud-name/image/upload/v1234567890/folder/image.jpg"
}
https://res.cloudinary.com/your-cloud-name/image/upload/w_500,h_500,c_fill/folder/image.jpg
https://res.cloudinary.com/your-cloud-name/image/upload/q_auto,f_auto/w_500,h_500,c_fill/folder/image.jpg
/var/www/innrcrcl
├── backend
├── frontend
├── ecosystem.config.js
└── nginx (nginx.conf)
module.exports = {
  apps: [
    {
      name: "innrcrcl-backend",
      script: "./backend/server.js",
      instances: "max",
      exec_mode: "cluster",
      env: {
        NODE_ENV: "production",
        PORT: 5000,
      },
    },
    {
      name: "innrcrcl-frontend",
      script: "serve",
      args: "-s ./frontend/build -l 3000",
      env: {
        NODE_ENV: "production",
      },
    },
  ],
};
pm2 start ecosystem.config.js
pm2 save
pm2 startup
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location /api/ {
        proxy_pass http://localhost:5000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }

    location / {
        proxy_pass http://localhost:3000/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
ln -s /etc/nginx/sites-available/innrcrcl /etc/nginx/sites-enabled/
nginx -t
systemctl reload nginx
sudo nano /etc/ssh/sshd_config
# Change: Port 22 -> Port 2222 (example)
PermitRootLogin no
sudo systemctl restart ssh
ufw allow 2222/tcp    # Your new SSH port
ufw allow 80/tcp      # HTTP
ufw allow 443/tcp     # HTTPS
ufw enable
ufw status
apt install fail2ban -y
systemctl enable fail2ban
systemctl start fail2ban
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades
pm2 install pm2-logrotate
pm2 set pm2-logrotate:max_size 10M
pm2 set pm2-logrotate:retain 7

