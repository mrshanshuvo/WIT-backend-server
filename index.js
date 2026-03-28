const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const admin = require("firebase-admin");
require("dotenv").config();

const app = express();

const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Environment Validation
if (!JWT_SECRET) {
  console.error("CRITICAL ERROR: JWT_SECRET is not defined in .env file.");
  process.exit(1);
}

if (!MONGO_URI) {
  console.error("CRITICAL ERROR: MONGO_URI is not defined in .env file.");
  process.exit(1);
}

// --------------------
// FIXED FIREBASE ADMIN
// --------------------
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      type: process.env.FIREBASE_TYPE,
      project_id: process.env.FIREBASE_PROJECT_ID,
      private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
      client_email: process.env.FIREBASE_CLIENT_EMAIL,
    }),
  });
}

// Middleware
app.use(
  cors({
    origin: [
      "https://simple-firebase-auth-9089a.web.app",
      "http://localhost:5173",
      "https://wit-web-client.vercel.app",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

// Connect to MongoDB
const client = new MongoClient(MONGO_URI);
let db,
  usersCollection,
  itemsCollection,
  recoveriesCollection,
  slidesCollection,
  blogsCollection,
  contactCollection,
  faqsCollection;

async function connectDB() {
  // Database
  db = client.db("whereisit");

  // Collections
  usersCollection = db.collection("users");
  itemsCollection = db.collection("items");
  recoveriesCollection = db.collection("recoveries");
  slidesCollection = db.collection("slides");
  blogsCollection = db.collection("blogs");
  contactCollection = db.collection("contactInfo");
  faqsCollection = db.collection("faqs");

  // Optional Seeding of Dummy Data (blogs and contact)
  const faqsCount = await faqsCollection.countDocuments();
  if (faqsCount === 0) {
    await faqsCollection.insertMany([
      {
        id: "report-lost",
        question: "How do I report a lost item?",
        answer: "Simply click on 'Report Lost Item' from your dashboard, fill in the item details including photos, description, location, and category. Your item will be instantly visible to our community of helpers.",
        category: "Reporting"
      },
      {
        id: "mark-found",
        question: "How can I mark an item as found?",
        answer: "Go to your dashboard, select the 'Found Items' section, and click 'Report Found Item'. Provide as much detail as possible to help identify the rightful owner quickly.",
        category: "Reporting"
      },
      {
        id: "contact-direct",
        question: "Can I contact the finder/owner directly?",
        answer: "Yes! Once a match is made, our secure messaging system allows you to communicate directly while protecting your personal information until you're ready to share contact details.",
        category: "Communication"
      },
      {
        id: "item-categories",
        question: "How are items categorized?",
        answer: "Items are organized into intuitive categories: Electronics, Documents, Jewelry, Clothing, Bags & Wallets, Keys, Books, and Other. This helps users quickly find what they're looking for.",
        category: "Organization"
      },
      {
        id: "personal-info-safe",
        question: "Is my personal information safe?",
        answer: "Absolutely. We use end-to-end encryption and never share your email or phone number publicly. Contact information is only shared with relevant parties after mutual agreement.",
        category: "Privacy"
      },
      {
        id: "match-notifications",
        question: "How quickly will I be notified of matches?",
        answer: "Our AI-powered matching system sends instant notifications when potential matches are found. Most users receive their first match within hours of posting.",
        category: "Notifications"
      },
      {
        id: "valuable-items",
        question: "What if my item is valuable or sensitive?",
        answer: "For valuable items, we recommend using our secure handoff locations and verification process. For sensitive documents, we have special protocols to ensure safe return.",
        category: "Safety"
      },
      {
        id: "service-fees",
        question: "Is there a fee for using WhereIsIt?",
        answer: "Basic services are completely free! We offer premium features like enhanced visibility and business solutions for a small fee, but reuniting lost items will always be free.",
        category: "Pricing"
      }
    ]);
  }

  const contactCount = await contactCollection.countDocuments();
  if (contactCount === 0) {
    await contactCollection.insertOne({
      email: "support@lostfound.com",
      phone: "+880123456789",
      address: "123 Green Street, Dhaka, Bangladesh",
      workingHours: "Mon-Fri 9:00 AM - 6:00 PM",
      facebook: "https://facebook.com/lostfound",
      twitter: "https://twitter.com/lostfound",
      instagram: "https://instagram.com/lostfound"
    });
  }

  const blogsCount = await blogsCollection.countDocuments();
  if (blogsCount === 0) {
    await blogsCollection.insertMany([
      {
        id: 1,
        title: "5 Tips to Keep Your Belongings Safe",
        date: "2025-10-26",
        author: "John Doe",
        category: "Safety",
        excerpt: "Learn practical steps to protect your valuables and avoid loss...",
        image: "https://images.unsplash.com/photo-1600180758895-9d5935e0a5d3",
        likes: 23,
        comments: 5
      },
      {
        id: 2,
        title: "What to Do if You Lose an Important Item",
        date: "2025-10-20",
        author: "Jane Smith",
        category: "Recovery",
        excerpt: "Follow these steps to increase the chances of recovering lost items...",
        image: "https://images.unsplash.com/photo-1573496359142-b8d87734a5a2",
        likes: 15,
        comments: 3
      },
      {
        id: 3,
        title: "Top 10 Most Common Lost Items",
        date: "2025-10-15",
        author: "Alice Johnson",
        category: "Insights",
        excerpt: "From keys to wallets, here are the items people lose most often...",
        image: "https://images.unsplash.com/photo-1591622770800-60117e2d6828",
        likes: 30,
        comments: 8
      },
      {
        id: 4,
        title: "How Technology Helps in Finding Lost Items",
        date: "2025-10-10",
        author: "Michael Brown",
        category: "Technology",
        excerpt: "Discover how apps and tracking devices improve recovery chances...",
        image: "https://images.unsplash.com/photo-1600180758895-0f5f1c5b20a2",
        likes: 42,
        comments: 12
      }
    ]);
  }

  // Connection test
  console.log("MongoDB connected (native driver)");
}

connectDB().catch((err) => {
  console.error("MongoDB connection error:", err);
  process.exit(1);
});

// Helper: Basic validation functions
function validateItemData(data) {
  const { postType, thumbnail, title, description, category, location, date } =
    data;

  if (
    !postType ||
    (postType !== "lost" && postType !== "found") ||
    !thumbnail ||
    typeof thumbnail !== "string" ||
    !title ||
    typeof title !== "string" ||
    !category ||
    typeof category !== "string" ||
    !location ||
    typeof location !== "string" ||
    !date ||
    isNaN(Date.parse(date))
  ) {
    return false;
  }
  return true;
}

// Auth middleware
// Updated protect middleware
const protect = async (req, res, next) => {
  let token;

  // 1. Check Authorization header for Firebase token
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer ")
  ) {
    token = req.headers.authorization.split(" ")[1];
    try {
      const decoded = await admin.auth().verifyIdToken(token);

      let user = await usersCollection.findOne({ email: decoded.email });

      if (!user) {
        // Create new user if not exists
        const newUser = {
          name: decoded.name || "Firebase User",
          email: decoded.email,
          uid: decoded.uid,
          isAdmin: false,
          photoURL: decoded.picture || "",
          createdAt: new Date(),
          updatedAt: new Date(),
        };
        const result = await usersCollection.insertOne(newUser);
        user = { ...newUser, _id: result.insertedId };
      } else {
        // Simple profile sync if missing data
        const syncUpdate = {};
        if (!user.photoURL && decoded.picture) syncUpdate.photoURL = decoded.picture;
        if ((!user.name || user.name === "Firebase User") && decoded.name) syncUpdate.name = decoded.name;

        if (Object.keys(syncUpdate).length > 0) {
          syncUpdate.updatedAt = new Date();
          await usersCollection.updateOne({ _id: user._id }, { $set: syncUpdate });
          user = { ...user, ...syncUpdate };
        }
      }

      req.user = user;
      return next();
    } catch (err) {
      console.error("Firebase token verification failed:", err.message);
      // Continue to JWT check
    }
  }

  // 2. Check cookies for JWT token
  token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Not authorized, no token" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    let user;
    if (decoded.userId) {
      user = await usersCollection.findOne({
        _id: new ObjectId(decoded.userId),
      });
    } else if (decoded.uid) {
      user = await usersCollection.findOne({ uid: decoded.uid });
    }

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("JWT token invalid:", err.message);
    return res.status(401).json({ message: "Not authorized, token failed" });
  }
};

// Helper to create JWT token
const createToken = (userIdOrUid, isUid = false) => {
  if (isUid)
    return jwt.sign({ uid: userIdOrUid }, JWT_SECRET, { expiresIn: "7d" });
  return jwt.sign({ userId: userIdOrUid }, JWT_SECRET, { expiresIn: "7d" });
};

// === Routes ===

// GET user info (protected) 🆗
app.get("/users/profile", protect, async (req, res) => {
  try {
    res.json({
      ...req.user,
    });
  } catch (err) {
    console.error("Error fetching profile:", err);
    res.status(500).json({ message: "Server error" });
  }
});
 
// Check if email already exists (public) 🆗
app.get("/users/check-email", async (req, res) => {
  const { email } = req.query;
  if (!email) {
    return res.status(400).json({ message: "Email parameter is required" });
  }

  try {
    const user = await usersCollection.findOne({ email });
    res.json({ exists: !!user });
  } catch (err) {
    console.error("Error checking email:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Firebase login 🆗
app.post("/users/firebase-login", async (req, res) => {
  const { idToken, name, photoURL } = req.body;

  if (!idToken)
    return res.status(400).json({ message: "No ID token provided" });

  try {
    const decodedToken = await admin.auth().verifyIdToken(idToken);
    const { uid, email } = decodedToken;

    let user = await usersCollection.findOne({ email });

    if (!user) {
      const now = new Date();
      user = {
        email,
        name: name || "User",
        password: "",
        uid,
        isAdmin: false,
        photoURL: photoURL || decodedToken.picture || "",
        createdAt: now,
        updatedAt: now,
      };
      const result = await usersCollection.insertOne(user);
      user._id = result.insertedId;
    } else {
      // Update only fields that are provided
      const updateData = {};
      if (name && user.name !== name) updateData.name = name;
      if (photoURL) updateData.photoURL = photoURL; // only overwrite if frontend sends it
      if (decodedToken.picture && !user.photoURL)
        updateData.photoURL = decodedToken.picture;

      if (Object.keys(updateData).length > 0) {
        updateData.updatedAt = new Date();
        await usersCollection.updateOne(
          { _id: user._id },
          { $set: updateData }
        );
        user = { ...user, ...updateData };
      }
    }

    const token = createToken(uid, true);
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.json({
      message: "Logged in with Firebase",
      user,
    });
  } catch (error) {
    console.error("Firebase token verification error:", error);
    res.status(401).json({ message: "Invalid Firebase ID token" });
  }
});

// Logout 🆗
app.post("/users/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  });
  res.json({ message: "Logged out" });
});

// Add lost/found item (protected) 🆗
app.post("/inventory", protect, async (req, res) => {
  try {
    if (!validateItemData(req.body)) {
      return res.status(400).json({ message: "Invalid item data" });
    }

    const {
      postType,
      thumbnail,
      title,
      description,
      category,
      location,
      date,
    } = req.body;

    const newItem = {
      postType,
      thumbnail,
      title,
      description: description || "",
      category,
      location,
      date: new Date(date),
      contactName: req.user.name,
      contactEmail: req.user.email,
      status: "not-recovered",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await itemsCollection.insertOne(newItem);
    res
      .status(201)
      .json({ message: "Item added successfully", itemId: result.insertedId });
  } catch (err) {
    console.error("Error adding item:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get single item (public) 🆗
app.get("/inventory/:id", async (req, res) => {
  try {
    const id = req.params.id;
    let item;

    if (ObjectId.isValid(id)) {
      item = await itemsCollection.findOne({
        $or: [{ _id: new ObjectId(id) }, { _id: id }],
      });
    } else {
      item = await itemsCollection.findOne({ _id: id });
    }

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    res.json(item);
  } catch (err) {
    console.error("Error fetching item:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get all items with filters (public) 🆗
app.get("/inventory", async (req, res) => {
  try {
    const { type, status, category, location, search } = req.query;
    const query = {};

    if (type && (type === "lost" || type === "found")) {
      query.postType = type;
    }

    if (status && (status === "active" || status === "recovered")) {
      query.status = status;
    }

    if (category) {
      query.category = category;
    }

    if (location) {
      query.location = { $regex: location, $options: "i" };
    }

    if (search) {
      query.$or = [
        { title: { $regex: search, $options: "i" } },
        { description: { $regex: search, $options: "i" } },
      ];
    }

    const items = await itemsCollection
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    res.json(items);
  } catch (err) {
    console.error("Error fetching items:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET API Endpoints for Banner Slides (public)
app.get("/highlights", async (req, res) => {
  try {
    const slides = await slidesCollection.find().toArray();
    res.json(slides);
  } catch (err) {
    console.error("Error fetching slides:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET Blogs (public)
app.get("/blogs", async (req, res) => {
  try {
    const blogs = await blogsCollection.find().sort({ date: -1 }).toArray();
    res.json(blogs);
  } catch (err) {
    console.error("Error fetching blogs:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET App Stats (public)
app.get("/stats", async (req, res) => {
  try {
    const totalItems = await itemsCollection.countDocuments();
    const itemsRecovered = await itemsCollection.countDocuments({ status: "recovered" });
    const usersCount = await usersCollection.countDocuments();

    let successRateNum = 0;
    if (totalItems > 0) {
      successRateNum = Math.round((itemsRecovered / totalItems) * 100);
    }

    res.json({
      totalItems,
      itemsRecovered,
      usersCount,
      successRate: successRateNum,
    });
  } catch (err) {
    console.error("Error fetching stats:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET Contact Info (public)
app.get("/contact-info", async (req, res) => {
  try {
    const info = await contactCollection.findOne({});
    res.json(info || {});
  } catch (err) {
    console.error("Error fetching contact info:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET FAQs (public)
app.get("/faqs", async (req, res) => {
  try {
    const faqs = await faqsCollection.find().toArray();
    res.json(faqs);
  } catch (err) {
    console.error("Error fetching faqs:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Update item (protected) 🆗
app.patch("/inventory/:id", protect, async (req, res) => {
  try {
    let { id } = req.params;

    // Clean up ID if it has unexpected characters
    id = id.split(":")[0].trim();

    let item;

    // Try finding by ObjectId
    if (ObjectId.isValid(id)) {
      item = await itemsCollection.findOne({ _id: new ObjectId(id) });
    }

    // If not found, try string ID
    if (!item) {
      item = await itemsCollection.findOne({ _id: id });
    }

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    // Ownership check (skip in development for testing)
    if (
      process.env.NODE_ENV !== "development" &&
      item.contactEmail !== req.user.email
    ) {
      return res.status(403).json({ message: "Not authorized" });
    }

    // Prepare update (only allow fields you want to update)
    const allowedFields = [
      "postType",
      "title",
      "description",
      "category",
      "location",
      "date",
      "thumbnail",
      "status",
    ];

    const updateData = {};
    allowedFields.forEach((field) => {
      if (req.body[field] !== undefined) {
        updateData[field] =
          field === "date" ? new Date(req.body.date) : req.body[field];
      }
    });

    updateData.updatedAt = new Date();

    const result = await itemsCollection.updateOne(
      { _id: item._id },
      { $set: updateData }
    );

    res.json({
      message: "Item updated successfully",
      modifiedCount: result.modifiedCount,
    });
  } catch (err) {
    console.error("PATCH ERROR:", {
      error: err.message,
      stack: err.stack,
      params: req.params,
      body: req.body,
      user: req.user,
    });
    res.status(500).json({
      message: "Update failed",
      error: process.env.NODE_ENV === "development" ? err.message : undefined,
    });
  }
});

// Report item recovery (protected) 🆗
app.post("/inventory/:id/recover", protect, async (req, res) => {
  try {
    const id = req.params.id;
    let item;

    // Try to find the item with both string ID and ObjectId
    if (ObjectId.isValid(id)) {
      item = await itemsCollection.findOne({
        $or: [{ _id: new ObjectId(id) }, { _id: id }],
      });
    } else {
      item = await itemsCollection.findOne({ _id: id });
    }

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    const {
      recoveredLocation,
      recoveredDate,
      notes,
      // Additional item data from payload
      postType,
      title,
      description,
      category,
      originalLocation,
      originalDate,
      thumbnail,
      originalOwner,
      recoveredBy,
    } = req.body;

    if (!recoveredLocation || !recoveredDate) {
      return res.status(400).json({ message: "Missing required fields" });
    }

    // Check if user is trying to recover their own item
    if (req.user.email === item.contactEmail) {
      return res
        .status(400)
        .json({ message: "You cannot recover your own item" });
    }

    const recDate = new Date(recoveredDate);
    if (isNaN(recDate)) {
      return res.status(400).json({ message: "Invalid recovery date" });
    }

    const recoveryData = {
      itemId: item._id,
      originalPostType: item.postType,
      originalItemData: {
        title: item.title,
        description: item.description,
        category: item.category,
        location: item.location,
        date: item.date,
        thumbnail: item.thumbnail,
      },
      originalOwner: {
        name: item.contactName,
        email: item.contactEmail,
      },
      recoveredBy: {
        userId: new ObjectId(req.user._id),
        name: req.user.name,
        email: req.user.email,
        photoURL: req.user.photoURL || null,
      },
      recoveredLocation,
      recoveredDate: recDate,
      notes: notes || "",
      recoveryStatus: "pending", // or "completed" based on your workflow
      createdAt: new Date(),
    };

    const session = client.startSession();
    try {
      await session.withTransaction(async () => {
        await recoveriesCollection.insertOne(recoveryData, { session });
        await itemsCollection.updateOne(
          { _id: item._id },
          { $set: { status: "recovered", updatedAt: new Date() } },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    res.json({
      message: "Item recovery recorded successfully",
      recovery: recoveryData,
    });
  } catch (err) {
    console.error("Error recording recovery:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Get recoveries for user (protected) 🆗
app.get("/recoveries", protect, async (req, res) => {
  try {
    const userId = new ObjectId(req.user._id);
    const userEmail = req.user.email;

    const recoveries = await recoveriesCollection
      .find({
        $or: [
          { "recoveredBy.userId": userId },
          { "originalOwner.email": userEmail },
        ],
      })
      .sort({ createdAt: -1 })
      .toArray();

    // Attach original item data (fallback if not found)
    const recoveriesWithItems = await Promise.all(
      recoveries.map(async (recovery) => {
        let item = null;
        try {
          // Try finding in itemsCollection
          if (ObjectId.isValid(recovery.itemId)) {
            item = await itemsCollection.findOne({
              _id: new ObjectId(recovery.itemId),
            });
          }
        } catch (err) {
          console.warn("Item lookup failed:", err.message);
        }

        // If item not found, fallback to embedded original data
        return {
          ...recovery,
          item: item || recovery.originalItemData || null,
        };
      })
    );

    res.json(recoveriesWithItems);
  } catch (err) {
    console.error("Error fetching recoveries:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get items for the current user (protected) 🆗
app.get("/my-items", protect, async (req, res) => {
  try {
    const email = req.query.email;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const items = await itemsCollection
      .find({ contactEmail: email })
      .sort({ createdAt: -1 })
      .toArray();

    res.json({
      emailUsed: email,
      itemsFound: items.length,
      items,
    });
  } catch (err) {
    console.error("Fetch my-items error:", err);
    res.status(500).json({ message: "Server error fetching items" });
  }
});

// Update recovery (protected) 🆗
app.patch("/recoveries/:id", protect, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: "Invalid recovery ID" });
    }

    // Only allow specific fields to be updated
    const allowedFields = [
      "recoveryStatus",
      "notes",
      "recoveredLocation",
      "recoveredDate",
    ];
    const filteredData = Object.keys(updateData)
      .filter((key) => allowedFields.includes(key))
      .reduce((obj, key) => {
        obj[key] = updateData[key];
        return obj;
      }, {});

    if (Object.keys(filteredData).length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    const result = await recoveriesCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: filteredData }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: "Recovery not found" });
    }

    const updatedRecovery = await recoveriesCollection.findOne({
      _id: new ObjectId(id),
    });

    res.status(200).json({
      message: "Recovery updated successfully",
      recovery: updatedRecovery,
    });
  } catch (err) {
    console.error("Error updating recovery:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Delete item (protected) 🆗
app.delete("/inventory/:id", protect, async (req, res) => {
  try {
    const id = req.params.id;
    let item;

    // Try to find the item with both string ID and ObjectId
    if (ObjectId.isValid(id)) {
      item = await itemsCollection.findOne({
        $or: [{ _id: new ObjectId(id) }, { _id: id }],
      });
    } else {
      item = await itemsCollection.findOne({ _id: id });
    }

    if (!item) {
      return res.status(404).json({ message: "Item not found" });
    }

    // Check if the user owns the item
    if (
      (!item.userId || item.userId.toString() !== req.user._id.toString()) &&
      item.contactEmail !== req.user.email
    ) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this item" });
    }

    // Use a transaction to ensure data consistency
    const session = client.startSession();
    try {
      await session.withTransaction(async () => {
        // Delete the item
        await itemsCollection.deleteOne({ _id: item._id }, { session });

        // Delete any associated recoveries
        await recoveriesCollection.deleteMany(
          { itemId: item._id },
          { session }
        );
      });
    } finally {
      await session.endSession();
    }

    res.json({ message: "Item deleted successfully" });
  } catch (err) {
    console.error("Error deleting item:", err);
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// Root route
app.get("/", (req, res) => {
  res.send("WhereIsIt backend server running!!");
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
