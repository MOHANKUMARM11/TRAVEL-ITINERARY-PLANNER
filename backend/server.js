// ============================================
// TRAVEL ITINERARY PLANNER - BACKEND SERVER
// Node.js + Express + MongoDB + JWT
// ============================================

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

// ============================================
// MIDDLEWARE
// ============================================
app.use(express.json());
app.use(cors());
app.use(express.urlencoded({ extended: true }));

// ============================================
// DATABASE CONNECTION
// ============================================
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/travel-planner', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB Connection Error:', err));

// ============================================
// MONGOOSE SCHEMAS
// ============================================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  profilePicture: { type: String, default: '' },
  preferences: {
    language: { type: String, default: 'en' },
    currency: { type: String, default: 'USD' }
  },
  savedDestinations: [{ type: mongoose.Schema.Types.ObjectId, ref: 'City' }]
}, { timestamps: true });

// Trip Schema
const tripSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tripName: { type: String, required: true },
  description: { type: String, default: '' },
  startDate: { type: Date, required: true },
  endDate: { type: Date, required: true },
  coverPhoto: { type: String, default: '' },
  cities: [{
    cityId: { type: mongoose.Schema.Types.ObjectId, ref: 'City' },
    arrivalDate: Date,
    departureDate: Date,
    order: Number
  }],
  activities: [{
    activityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Activity' },
    cityId: { type: mongoose.Schema.Types.ObjectId, ref: 'City' },
    date: Date,
    startTime: String,
    endTime: String,
    cost: { type: Number, default: 0 },
    notes: String
  }],
  budget: {
    transport: { type: Number, default: 0 },
    accommodation: { type: Number, default: 0 },
    activities: { type: Number, default: 0 },
    meals: { type: Number, default: 0 },
    others: { type: Number, default: 0 },
    total: { type: Number, default: 0 }
  },
  isPublic: { type: Boolean, default: false },
  shareToken: { type: String, unique: true, sparse: true }
}, { timestamps: true });

// City Schema
const citySchema = new mongoose.Schema({
  name: { type: String, required: true },
  country: { type: String, required: true },
  description: { type: String, default: '' },
  imageUrl: { type: String, default: '' },
  coordinates: {
    latitude: Number,
    longitude: Number
  },
  costIndex: { type: Number, min: 1, max: 5, default: 3 },
  popularity: { type: Number, default: 0 },
  tags: [String],
  bestTimeToVisit: String,
  currency: String,
  timezone: String
}, { timestamps: true });

// Activity Schema
const activitySchema = new mongoose.Schema({
  cityId: { type: mongoose.Schema.Types.ObjectId, ref: 'City', required: true },
  name: { type: String, required: true },
  description: { type: String, default: '' },
  type: { 
    type: String, 
    enum: ['sightseeing', 'adventure', 'food', 'culture', 'relaxation', 'shopping', 'nightlife'],
    default: 'sightseeing'
  },
  duration: { type: Number, default: 2 }, // in hours
  estimatedCost: { type: Number, default: 0 },
  imageUrl: { type: String, default: '' },
  location: String,
  rating: { type: Number, min: 1, max: 5, default: 4 },
  tags: [String]
}, { timestamps: true });

// Models
const User = mongoose.model('User', userSchema);
const Trip = mongoose.model('Trip', tripSchema);
const City = mongoose.model('City', citySchema);
const Activity = mongoose.model('Activity', activitySchema);

// ============================================
// JWT AUTHENTICATION MIDDLEWARE
// ============================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin check middleware
const isAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
};

// ============================================
// AUTHENTICATION ROUTES
// ============================================

// Register new user
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Registration failed', details: error.message });
  }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      { userId: user._id, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        profilePicture: user.profilePicture
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Login failed', details: error.message });
  }
});

// ============================================
// USER ROUTES
// ============================================

// Get user profile
app.get('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId)
      .select('-password')
      .populate('savedDestinations');
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile', details: error.message });
  }
});

// Update user profile
app.put('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    const { name, profilePicture, preferences } = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      { name, profilePicture, preferences },
      { new: true, runValidators: true }
    ).select('-password');

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update profile', details: error.message });
  }
});

// Delete user account
app.delete('/api/users/profile', authenticateToken, async (req, res) => {
  try {
    // Delete user's trips
    await Trip.deleteMany({ userId: req.user.userId });
    
    // Delete user
    await User.findByIdAndDelete(req.user.userId);

    res.json({ message: 'Account deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete account', details: error.message });
  }
});

// ============================================
// TRIP ROUTES
// ============================================

// Create new trip
app.post('/api/trips', authenticateToken, async (req, res) => {
  try {
    const { tripName, description, startDate, endDate, coverPhoto } = req.body;

    if (!tripName || !startDate || !endDate) {
      return res.status(400).json({ error: 'Trip name, start date, and end date are required' });
    }

    const trip = new Trip({
      userId: req.user.userId,
      tripName,
      description,
      startDate,
      endDate,
      coverPhoto
    });

    await trip.save();

    res.status(201).json({ message: 'Trip created successfully', trip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create trip', details: error.message });
  }
});

// Get all trips for logged-in user
app.get('/api/trips', authenticateToken, async (req, res) => {
  try {
    const trips = await Trip.find({ userId: req.user.userId })
      .populate('cities.cityId')
      .sort({ createdAt: -1 });

    res.json(trips);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch trips', details: error.message });
  }
});

// Get single trip by ID
app.get('/api/trips/:id', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    })
    .populate('cities.cityId')
    .populate('activities.activityId')
    .populate('activities.cityId');

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    res.json(trip);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch trip', details: error.message });
  }
});

// Update trip
app.put('/api/trips/:id', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.userId },
      req.body,
      { new: true, runValidators: true }
    ).populate('cities.cityId');

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    res.json({ message: 'Trip updated successfully', trip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update trip', details: error.message });
  }
});

// Delete trip
app.delete('/api/trips/:id', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOneAndDelete({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    res.json({ message: 'Trip deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete trip', details: error.message });
  }
});

// Add city to trip
app.post('/api/trips/:id/cities', authenticateToken, async (req, res) => {
  try {
    const { cityId, arrivalDate, departureDate, order } = req.body;

    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    trip.cities.push({ cityId, arrivalDate, departureDate, order });
    await trip.save();

    const updatedTrip = await Trip.findById(trip._id).populate('cities.cityId');

    res.json({ message: 'City added to trip', trip: updatedTrip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add city', details: error.message });
  }
});

// Remove city from trip
app.delete('/api/trips/:id/cities/:cityId', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    trip.cities = trip.cities.filter(c => c.cityId.toString() !== req.params.cityId);
    await trip.save();

    res.json({ message: 'City removed from trip', trip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove city', details: error.message });
  }
});

// Add activity to trip
app.post('/api/trips/:id/activities', authenticateToken, async (req, res) => {
  try {
    const { activityId, cityId, date, startTime, endTime, cost, notes } = req.body;

    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    trip.activities.push({ activityId, cityId, date, startTime, endTime, cost, notes });
    
    // Update budget
    trip.budget.activities += cost || 0;
    trip.budget.total = trip.budget.transport + trip.budget.accommodation + 
                        trip.budget.activities + trip.budget.meals + trip.budget.others;
    
    await trip.save();

    const updatedTrip = await Trip.findById(trip._id)
      .populate('activities.activityId')
      .populate('activities.cityId');

    res.json({ message: 'Activity added to trip', trip: updatedTrip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add activity', details: error.message });
  }
});

// Remove activity from trip
app.delete('/api/trips/:id/activities/:activityId', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    const activityIndex = trip.activities.findIndex(
      a => a.activityId.toString() === req.params.activityId
    );

    if (activityIndex > -1) {
      const activityCost = trip.activities[activityIndex].cost || 0;
      trip.budget.activities -= activityCost;
      trip.budget.total -= activityCost;
      trip.activities.splice(activityIndex, 1);
    }

    await trip.save();

    res.json({ message: 'Activity removed from trip', trip });
  } catch (error) {
    res.status(500).json({ error: 'Failed to remove activity', details: error.message });
  }
});

// Update trip budget
app.put('/api/trips/:id/budget', authenticateToken, async (req, res) => {
  try {
    const { transport, accommodation, activities, meals, others } = req.body;

    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    trip.budget = {
      transport: transport || 0,
      accommodation: accommodation || 0,
      activities: activities || 0,
      meals: meals || 0,
      others: others || 0,
      total: (transport || 0) + (accommodation || 0) + (activities || 0) + 
             (meals || 0) + (others || 0)
    };

    await trip.save();

    res.json({ message: 'Budget updated successfully', budget: trip.budget });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update budget', details: error.message });
  }
});

// Make trip public/shareable
app.post('/api/trips/:id/share', authenticateToken, async (req, res) => {
  try {
    const trip = await Trip.findOne({ 
      _id: req.params.id,
      userId: req.user.userId 
    });

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found' });
    }

    if (!trip.shareToken) {
      trip.shareToken = crypto.randomBytes(16).toString('hex');
    }
    trip.isPublic = true;

    await trip.save();

    res.json({ 
      message: 'Trip is now public',
      shareUrl: `${req.protocol}://${req.get('host')}/shared/${trip.shareToken}`
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to share trip', details: error.message });
  }
});

// Get public trip by share token
app.get('/api/shared/:token', async (req, res) => {
  try {
    const trip = await Trip.findOne({ 
      shareToken: req.params.token,
      isPublic: true 
    })
    .populate('cities.cityId')
    .populate('activities.activityId')
    .populate('activities.cityId')
    .populate('userId', 'name');

    if (!trip) {
      return res.status(404).json({ error: 'Trip not found or not public' });
    }

    res.json(trip);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch trip', details: error.message });
  }
});

// ============================================
// CITY ROUTES
// ============================================

// Get all cities with filters
app.get('/api/cities', async (req, res) => {
  try {
    const { country, costIndex, tags, search } = req.query;
    
    let query = {};
    
    if (country) query.country = country;
    if (costIndex) query.costIndex = parseInt(costIndex);
    if (tags) query.tags = { $in: tags.split(',') };
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { country: { $regex: search, $options: 'i' } }
      ];
    }

    const cities = await City.find(query).sort({ popularity: -1 });

    res.json(cities);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch cities', details: error.message });
  }
});

// Get single city
app.get('/api/cities/:id', async (req, res) => {
  try {
    const city = await City.findById(req.params.id);

    if (!city) {
      return res.status(404).json({ error: 'City not found' });
    }

    res.json(city);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch city', details: error.message });
  }
});

// Create new city (admin only)
app.post('/api/cities', authenticateToken, isAdmin, async (req, res) => {
  try {
    const city = new City(req.body);
    await city.save();

    res.status(201).json({ message: 'City created successfully', city });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create city', details: error.message });
  }
});

// Update city (admin only)
app.put('/api/cities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const city = await City.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!city) {
      return res.status(404).json({ error: 'City not found' });
    }

    res.json({ message: 'City updated successfully', city });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update city', details: error.message });
  }
});

// Delete city (admin only)
app.delete('/api/cities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const city = await City.findByIdAndDelete(req.params.id);

    if (!city) {
      return res.status(404).json({ error: 'City not found' });
    }

    res.json({ message: 'City deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete city', details: error.message });
  }
});

// ============================================
// ACTIVITY ROUTES
// ============================================

// Get activities by city with filters
app.get('/api/activities', async (req, res) => {
  try {
    const { cityId, type, minCost, maxCost, search } = req.query;
    
    let query = {};
    
    if (cityId) query.cityId = cityId;
    if (type) query.type = type;
    if (minCost) query.estimatedCost = { $gte: parseInt(minCost) };
    if (maxCost) query.estimatedCost = { ...query.estimatedCost, $lte: parseInt(maxCost) };
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }

    const activities = await Activity.find(query).populate('cityId');

    res.json(activities);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activities', details: error.message });
  }
});

// Get single activity
app.get('/api/activities/:id', async (req, res) => {
  try {
    const activity = await Activity.findById(req.params.id).populate('cityId');

    if (!activity) {
      return res.status(404).json({ error: 'Activity not found' });
    }

    res.json(activity);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch activity', details: error.message });
  }
});

// Create new activity (admin only)
app.post('/api/activities', authenticateToken, isAdmin, async (req, res) => {
  try {
    const activity = new Activity(req.body);
    await activity.save();

    res.status(201).json({ message: 'Activity created successfully', activity });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create activity', details: error.message });
  }
});

// Update activity (admin only)
app.put('/api/activities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const activity = await Activity.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );

    if (!activity) {
      return res.status(404).json({ error: 'Activity not found' });
    }

    res.json({ message: 'Activity updated successfully', activity });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update activity', details: error.message });
  }
});

// Delete activity (admin only)
app.delete('/api/activities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const activity = await Activity.findByIdAndDelete(req.params.id);

    if (!activity) {
      return res.status(404).json({ error: 'Activity not found' });
    }

    res.json({ message: 'Activity deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete activity', details: error.message });
  }
});

// ============================================
// ADMIN ROUTES
// ============================================

// Get admin statistics
app.get('/api/admin/stats', authenticateToken, isAdmin, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalTrips = await Trip.countDocuments();
    const totalCities = await City.countDocuments();
    const totalActivities = await Activity.countDocuments();
    
    // Get popular cities
    const popularCities = await City.find().sort({ popularity: -1 }).limit(10);
    
    // Get recent users
    const recentUsers = await User.find()
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(10);
    
    // Get trips created in last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentTrips = await Trip.countDocuments({ 
      createdAt: { $gte: thirtyDaysAgo } 
    });

    res.json({
      totalUsers,
      totalTrips,
      totalCities,
      totalActivities,
      recentTrips,
      popularCities,
      recentUsers
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch statistics', details: error.message });
  }
});

// Get all users (admin only)
app.get('/api/admin/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    const users = await User.find()
      .select('-password')
      .sort({ createdAt: -1 });

    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users', details: error.message });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    // Don't allow admin to delete themselves
    if (req.params.id === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete your own account' });
    }

    const user = await User.findByIdAndDelete(req.params.id);

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Delete user's trips
    await Trip.deleteMany({ userId: req.params.id });

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user', details: error.message });
  }
});

// ============================================
// RECOMMENDATION ROUTES (AI-powered)
// ============================================

// Get recommended destinations based on user preferences
app.get('/api/recommendations/destinations', authenticateToken, async (req, res) => {
  try {
    // Simple recommendation logic - can be enhanced with ML
    const user = await User.findById(req.user.userId);
    const userTrips = await Trip.find({ userId: req.user.userId })
      .populate('cities.cityId');

    // Get cities user hasn't visited
    const visitedCityIds = userTrips.flatMap(trip => 
      trip.cities.map(c => c.cityId._id.toString())
    );

    const recommendations = await City.find({
      _id: { $nin: visitedCityIds }
    })
    .sort({ popularity: -1 })
    .limit(6);

    res.json(recommendations);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch recommendations', details: error.message });
  }
});

// ============================================
// SEED DATA ENDPOINT (for testing)
// ============================================
app.post('/api/seed', async (req, res) => {
  try {
    // Clear existing data
    await City.deleteMany({});
    await Activity.deleteMany({});

    // Seed cities
    const cities = await City.insertMany([
      {
        name: 'Paris',
        country: 'France',
        description: 'The City of Light, known for art, fashion, and culture',
        imageUrl: 'https://images.unsplash.com/photo-1502602898657-3e91760cbb34',
        coordinates: { latitude: 48.8566, longitude: 2.3522 },
        costIndex: 4,
        popularity: 100,
        tags: ['romantic', 'historic', 'culture', 'food'],
        bestTimeToVisit: 'April to June, September to October',
        currency: 'EUR',
        timezone: 'CET'
      },
      {
        name: 'Tokyo',
        country: 'Japan',
        description: 'A vibrant metropolis blending tradition and modernity',
        imageUrl: 'https://images.unsplash.com/photo-1540959733332-eab4deabeeaf',
        coordinates: { latitude: 35.6762, longitude: 139.6503 },
        costIndex: 4,
        popularity: 95,
        tags: ['modern', 'culture', 'food', 'technology'],
        bestTimeToVisit: 'March to May, September to November',
        currency: 'JPY',
        timezone: 'JST'
      },
      {
        name: 'Bali',
        country: 'Indonesia',
        description: 'Tropical paradise with beaches, temples, and rice terraces',
        imageUrl: 'https://images.unsplash.com/photo-1537996194471-e657df975ab4',
        coordinates: { latitude: -8.3405, longitude: 115.0920 },
        costIndex: 2,
        popularity: 90,
        tags: ['beach', 'relaxation', 'culture', 'nature'],
        bestTimeToVisit: 'April to October',
        currency: 'IDR',
        timezone: 'WITA'
      },
      {
        name: 'New York',
        country: 'USA',
        description: 'The city that never sleeps, iconic skyline and culture',
        imageUrl: 'https://images.unsplash.com/photo-1496442226666-8d4d0e62e6e9',
        coordinates: { latitude: 40.7128, longitude: -74.0060 },
        costIndex: 5,
        popularity: 98,
        tags: ['urban', 'culture', 'shopping', 'nightlife'],
        bestTimeToVisit: 'April to June, September to November',
        currency: 'USD',
        timezone: 'EST'
      },
      {
        name: 'Dubai',
        country: 'UAE',
        description: 'Luxury shopping, ultramodern architecture, and desert safaris',
        imageUrl: 'https://images.unsplash.com/photo-1512453979798-5ea266f8880c',
        coordinates: { latitude: 25.2048, longitude: 55.2708 },
        costIndex: 4,
        popularity: 85,
        tags: ['luxury', 'modern', 'shopping', 'adventure'],
        bestTimeToVisit: 'November to March',
        currency: 'AED',
        timezone: 'GST'
      },
      {
        name: 'Rome',
        country: 'Italy',
        description: 'Ancient history, stunning architecture, and delicious cuisine',
        imageUrl: 'https://images.unsplash.com/photo-1552832230-c0197dd311b5',
        coordinates: { latitude: 41.9028, longitude: 12.4964 },
        costIndex: 3,
        popularity: 92,
        tags: ['historic', 'culture', 'food', 'art'],
        bestTimeToVisit: 'April to June, September to October',
        currency: 'EUR',
        timezone: 'CET'
      }
    ]);

    // Seed activities for Paris
    const parisId = cities.find(c => c.name === 'Paris')._id;
    await Activity.insertMany([
      {
        cityId: parisId,
        name: 'Eiffel Tower Visit',
        description: 'Visit the iconic iron lattice tower',
        type: 'sightseeing',
        duration: 3,
        estimatedCost: 25,
        imageUrl: 'https://images.unsplash.com/photo-1511739001486-6bfe10ce785f',
        location: 'Champ de Mars',
        rating: 5,
        tags: ['iconic', 'landmark', 'views']
      },
      {
        cityId: parisId,
        name: 'Louvre Museum',
        description: 'World\'s largest art museum',
        type: 'culture',
        duration: 4,
        estimatedCost: 20,
        imageUrl: 'https://images.unsplash.com/photo-1499856871958-5b9627545d1a',
        location: 'Rue de Rivoli',
        rating: 5,
        tags: ['art', 'museum', 'culture']
      },
      {
        cityId: parisId,
        name: 'Seine River Cruise',
        description: 'Romantic boat tour along the Seine',
        type: 'relaxation',
        duration: 2,
        estimatedCost: 15,
        location: 'Seine River',
        rating: 4,
        tags: ['romantic', 'cruise', 'sightseeing']
      }
    ]);

    // Seed activities for Tokyo
    const tokyoId = cities.find(c => c.name === 'Tokyo')._id;
    await Activity.insertMany([
      {
        cityId: tokyoId,
        name: 'Shibuya Crossing Experience',
        description: 'World\'s busiest pedestrian crossing',
        type: 'sightseeing',
        duration: 1,
        estimatedCost: 0,
        location: 'Shibuya',
        rating: 4,
        tags: ['urban', 'iconic', 'free']
      },
      {
        cityId: tokyoId,
        name: 'Sushi Making Class',
        description: 'Learn to make authentic sushi',
        type: 'food',
        duration: 3,
        estimatedCost: 80,
        location: 'Central Tokyo',
        rating: 5,
        tags: ['food', 'experience', 'culture']
      },
      {
        cityId: tokyoId,
        name: 'Mount Fuji Day Trip',
        description: 'Visit Japan\'s iconic mountain',
        type: 'adventure',
        duration: 10,
        estimatedCost: 100,
        location: 'Mount Fuji',
        rating: 5,
        tags: ['nature', 'adventure', 'iconic']
      }
    ]);

    res.json({ message: 'Database seeded successfully', citiesCount: cities.length });
  } catch (error) {
    res.status(500).json({ error: 'Failed to seed database', details: error.message });
  }
});

// ============================================
// ROOT ROUTE
// ============================================
app.get('/', (req, res) => {
  res.json({
    message: 'Travel Itinerary Planner API',
    version: '1.0.0',
    endpoints: {
      auth: '/api/auth/signup, /api/auth/login',
      users: '/api/users/profile',
      trips: '/api/trips',
      cities: '/api/cities',
      activities: '/api/activities',
      admin: '/api/admin/stats',
      recommendations: '/api/recommendations/destinations',
      shared: '/api/shared/:token',
      seed: '/api/seed (POST)'
    }
  });
});

// ============================================
// ERROR HANDLING MIDDLEWARE
// ============================================
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    error: 'Something went wrong!',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// ============================================
// START SERVER
// ============================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 API endpoint: http://localhost:${PORT}`);
});