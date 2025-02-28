var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc2) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc2 = __getOwnPropDesc(from, key)) || desc2.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  bookings: () => bookings,
  comparisons: () => comparisons,
  equipment: () => equipment,
  insertBookingSchema: () => insertBookingSchema,
  insertEquipmentSchema: () => insertEquipmentSchema,
  insertRecommendationSchema: () => insertRecommendationSchema,
  insertUserSchema: () => insertUserSchema,
  paymentSessionSchema: () => paymentSessionSchema,
  receiptSchema: () => receiptSchema,
  recommendations: () => recommendations,
  reviewSchema: () => reviewSchema,
  reviews: () => reviews,
  updateProfileSchema: () => updateProfileSchema,
  users: () => users
});
import { pgTable, text, serial, integer, boolean, timestamp, json } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users, equipment, bookings, reviews, comparisons, recommendations, insertUserSchema, insertEquipmentSchema, insertBookingSchema, insertRecommendationSchema, updateProfileSchema, reviewSchema, paymentSessionSchema, receiptSchema;
var init_schema = __esm({
  "shared/schema.ts"() {
    "use strict";
    users = pgTable("users", {
      id: serial("id").primaryKey(),
      username: text("username").notNull().unique(),
      password: text("password").notNull(),
      isAdmin: boolean("is_admin").notNull().default(false),
      name: text("name").notNull(),
      contact: text("contact"),
      language: text("language").notNull().default("en"),
      imageUrl: text("image_url"),
      preferences: json("preferences").$type().default({
        preferredCategories: [],
        preferredLocations: [],
        priceRange: { min: 0, max: 1e5 },
        features: []
      }).notNull()
    });
    equipment = pgTable("equipment", {
      id: serial("id").primaryKey(),
      ownerId: integer("owner_id").notNull(),
      name: text("name").notNull(),
      description: text("description").notNull(),
      category: text("category").notNull(),
      dailyRate: integer("daily_rate").notNull(),
      imageUrl: text("image_url").notNull(),
      location: text("location").notNull(),
      availability: boolean("availability").notNull().default(true),
      specs: json("specs").$type().default({}).notNull(),
      features: json("features").$type().default([]).notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow(),
      popularity: integer("popularity").notNull().default(0)
    });
    bookings = pgTable("bookings", {
      id: serial("id").primaryKey(),
      equipmentId: integer("equipment_id").notNull(),
      userId: integer("user_id").notNull(),
      startDate: timestamp("start_date").notNull(),
      endDate: timestamp("end_date").notNull(),
      totalPrice: integer("total_price").notNull(),
      status: text("status").notNull().default("pending"),
      razorpayOrderId: text("razorpay_order_id"),
      razorpayPaymentId: text("razorpay_payment_id"),
      isRated: boolean("is_rated").notNull().default(false),
      createdAt: timestamp("created_at").notNull().defaultNow(),
      lastStatusUpdate: timestamp("last_status_update").notNull().defaultNow()
    });
    reviews = pgTable("reviews", {
      id: serial("id").primaryKey(),
      userId: integer("user_id").notNull(),
      equipmentId: integer("equipment_id").notNull(),
      rating: integer("rating").notNull(),
      comment: text("comment").notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow()
    });
    comparisons = pgTable("comparisons", {
      id: serial("id").primaryKey(),
      userId: integer("user_id").notNull(),
      equipmentIds: integer("equipment_ids").array().notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow()
    });
    recommendations = pgTable("recommendations", {
      id: serial("id").primaryKey(),
      userId: integer("user_id").notNull(),
      equipmentId: integer("equipment_id").notNull(),
      score: integer("score").notNull(),
      reason: text("reason").notNull(),
      createdAt: timestamp("created_at").notNull().defaultNow()
    });
    insertUserSchema = createInsertSchema(users).pick({
      username: true,
      password: true,
      name: true,
      language: true
    });
    insertEquipmentSchema = createInsertSchema(equipment).omit({
      id: true,
      createdAt: true,
      popularity: true
    }).extend({
      specs: z.record(z.string(), z.string()).default({}),
      features: z.array(z.string()).default([])
    });
    insertBookingSchema = createInsertSchema(bookings).omit({
      id: true,
      createdAt: true,
      lastStatusUpdate: true,
      isRated: true
    }).extend({
      startDate: z.coerce.date(),
      endDate: z.coerce.date(),
      status: z.string().default("pending"),
      totalPrice: z.number().optional()
    });
    insertRecommendationSchema = createInsertSchema(recommendations).omit({
      id: true,
      createdAt: true
    });
    updateProfileSchema = z.object({
      name: z.string().min(1, "Name is required"),
      contact: z.string().optional(),
      language: z.string().optional(),
      imageUrl: z.string().optional()
    });
    reviewSchema = z.object({
      id: z.number().optional(),
      userId: z.number(),
      equipmentId: z.number(),
      rating: z.number().min(1, "Please select a rating").max(5, "Rating cannot exceed 5 stars"),
      comment: z.string().min(10, "Please provide a detailed comment (minimum 10 characters)").max(500, "Comment is too long (maximum 500 characters)"),
      createdAt: z.date().optional()
    });
    paymentSessionSchema = z.object({
      id: z.string(),
      url: z.string(),
      bookingId: z.number()
    });
    receiptSchema = z.object({
      bookingId: z.number(),
      status: z.string(),
      timestamp: z.string(),
      receipt_url: z.string().nullable()
    });
  }
});

// server/db.ts
var db_exports = {};
__export(db_exports, {
  db: () => db,
  pool: () => pool
});
import { Pool, neonConfig } from "@neondatabase/serverless";
import { drizzle } from "drizzle-orm/neon-serverless";
import ws from "ws";
import dotenv from "dotenv";
async function testConnection(retries = 5) {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await pool.connect();
      await client.query("SELECT NOW()");
      client.release();
      console.log("Database connection verified successfully");
      return;
    } catch (err) {
      console.error(`Database connection attempt ${i + 1} failed:`, err);
      if (i === retries - 1) {
        console.error("All database connection attempts failed");
        process.exit(1);
      }
      await new Promise((resolve) => setTimeout(resolve, 1e3 * (i + 1)));
    }
  }
}
var pool, db;
var init_db = __esm({
  "server/db.ts"() {
    "use strict";
    init_schema();
    dotenv.config();
    neonConfig.webSocketConstructor = ws;
    neonConfig.useSecureWebSocket = true;
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL must be set in environment variables");
    }
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      connectionTimeoutMillis: 5e3,
      max: 20,
      // Maximum number of clients in the pool
      idleTimeoutMillis: 3e4,
      keepAlive: true,
      ssl: true
    });
    pool.on("error", (err) => {
      console.error("Unexpected error on idle database client", err);
      process.exit(-1);
    });
    db = drizzle(pool, { schema: schema_exports });
    testConnection().catch((err) => {
      console.error("Failed to establish database connection:", err);
      process.exit(1);
    });
  }
});

// server/index.ts
import express3 from "express";

// server/routes.ts
import { createServer } from "http";

// server/auth.ts
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session2 from "express-session";
import { scrypt, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";

// server/storage.ts
init_schema();
init_db();
init_db();
import { eq, and, gte, lte, or, desc } from "drizzle-orm";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { sql } from "drizzle-orm";
var PostgresSessionStore = connectPg(session);
var DatabaseStorage = class {
  sessionStore;
  constructor() {
  }
  async init() {
    const maxRetries = 5;
    const retryDelay = 5e3;
    let retries = maxRetries;
    while (retries > 0) {
      try {
        await pool.query("SELECT NOW()");
        console.log("Database connection verified successfully");
        this.sessionStore = new PostgresSessionStore({
          pool,
          tableName: "session",
          createTableIfMissing: true,
          pruneSessionInterval: 60
          // Prune expired sessions every 60 seconds
        });
        console.log("Session store initialized successfully");
        return;
      } catch (error) {
        console.error(`Database initialization attempt failed (${retries} retries left):`, error);
        retries--;
        if (retries > 0) {
          console.log(`Retrying in ${retryDelay / 1e3} seconds...`);
          await new Promise((resolve) => setTimeout(resolve, retryDelay));
        } else {
          console.error("All database initialization attempts failed");
        }
      }
    }
  }
  async getUser(id) {
    try {
      const [user] = await db.select().from(users).where(eq(users.id, id));
      return user;
    } catch (error) {
      console.error("Error in getUser:", error);
      throw new Error("Failed to fetch user");
    }
  }
  async getUserByUsername(username) {
    try {
      const [user] = await db.select().from(users).where(eq(users.username, username));
      return user;
    } catch (error) {
      console.error("Error in getUserByUsername:", error);
      throw new Error("Failed to fetch user by username");
    }
  }
  async createUser(insertUser) {
    try {
      const [user] = await db.insert(users).values(insertUser).returning();
      return user;
    } catch (error) {
      console.error("Error in createUser:", error);
      throw new Error("Failed to create user");
    }
  }
  async updateUser(id, data) {
    try {
      const [user] = await db.update(users).set(data).where(eq(users.id, id)).returning();
      if (!user) throw new Error("User not found");
      return user;
    } catch (error) {
      console.error("Error in updateUser:", error);
      throw new Error("Failed to update user");
    }
  }
  async getEquipment(id) {
    try {
      const [equip] = await db.select().from(equipment).where(eq(equipment.id, id));
      return equip;
    } catch (error) {
      console.error("Error in getEquipment:", error);
      throw new Error("Failed to fetch equipment");
    }
  }
  async listEquipment() {
    try {
      const equipment2 = await db.select().from(equipment);
      console.log("Database query result:", equipment2);
      const transformedEquipment = equipment2.map((item) => ({
        ...item,
        availability: Boolean(item.availability)
      }));
      return transformedEquipment;
    } catch (error) {
      console.error("Error in listEquipment:", error);
      throw new Error("Failed to list equipment");
    }
  }
  async listEquipmentByOwner(ownerId) {
    try {
      const equipment2 = await db.select().from(equipment).where(eq(equipment.ownerId, ownerId));
      console.log(`Equipment for owner ${ownerId}:`, equipment2);
      const transformedEquipment = equipment2.map((item) => ({
        ...item,
        availability: Boolean(item.availability)
      }));
      return transformedEquipment;
    } catch (error) {
      console.error("Error in listEquipmentByOwner:", error);
      throw new Error("Failed to list equipment by owner");
    }
  }
  async createEquipment(insertEquipment) {
    try {
      const [equipment2] = await db.insert(equipment).values({
        ownerId: insertEquipment.ownerId,
        name: insertEquipment.name,
        description: insertEquipment.description,
        category: insertEquipment.category,
        dailyRate: insertEquipment.dailyRate,
        location: insertEquipment.location,
        imageUrl: insertEquipment.imageUrl,
        specs: insertEquipment.specs ?? {},
        features: insertEquipment.features ?? [],
        availability: true
      }).returning();
      if (!equipment2) {
        throw new Error("Failed to create equipment record");
      }
      return equipment2;
    } catch (error) {
      console.error("Error in createEquipment:", error);
      throw new Error("Failed to create equipment");
    }
  }
  async updateEquipment(id, data) {
    try {
      const [equipment2] = await db.update(equipment).set(data).where(eq(equipment.id, id)).returning();
      if (!equipment2) {
        throw new Error("Equipment not found");
      }
      return equipment2;
    } catch (error) {
      console.error("Error updating equipment:", error);
      throw new Error("Failed to update equipment");
    }
  }
  async deleteEquipment(id) {
    try {
      await db.delete(equipment).where(eq(equipment.id, id));
    } catch (error) {
      console.error("Error in deleteEquipment:", error);
      throw new Error("Failed to delete equipment");
    }
  }
  async getBooking(id) {
    try {
      console.log(`Fetching booking with ID: ${id}`);
      const [booking] = await db.select().from(bookings).where(eq(bookings.id, id));
      if (!booking) {
        console.log(`No booking found with ID: ${id}`);
        return void 0;
      }
      console.log(`Found booking:`, booking);
      return booking;
    } catch (error) {
      console.error("Error in getBooking:", error);
      throw new Error("Failed to fetch booking");
    }
  }
  async findBookingByRazorpayOrderId(orderId) {
    try {
      const [booking] = await db.select().from(bookings).where(eq(bookings.razorpayOrderId, orderId));
      return booking;
    } catch (error) {
      console.error("Error finding booking by Razorpay order ID:", error);
      throw new Error("Failed to find booking by Razorpay order ID");
    }
  }
  async listBookings(userId) {
    try {
      if (userId) {
        return await db.select().from(bookings).where(eq(bookings.userId, userId)).orderBy(desc(bookings.createdAt));
      }
      return await db.select().from(bookings).orderBy(desc(bookings.createdAt));
    } catch (error) {
      console.error("Error listing bookings:", error);
      return [];
    }
  }
  async createBooking(insertBooking) {
    try {
      const [booking] = await db.insert(bookings).values({
        ...insertBooking,
        status: insertBooking.status || "pending",
        createdAt: /* @__PURE__ */ new Date(),
        lastStatusUpdate: /* @__PURE__ */ new Date()
      }).returning();
      return booking;
    } catch (error) {
      console.error("Error in createBooking:", error);
      throw new Error("Failed to create booking");
    }
  }
  async updateBookingStatus(id, status) {
    try {
      const [booking] = await db.update(bookings).set({
        status,
        lastStatusUpdate: /* @__PURE__ */ new Date()
      }).where(eq(bookings.id, id)).returning();
      if (!booking) throw new Error("Booking not found");
      return booking;
    } catch (error) {
      console.error("Error in updateBookingStatus:", error);
      throw new Error("Failed to update booking status");
    }
  }
  async updateBooking(id, data) {
    try {
      const [booking] = await db.update(bookings).set({
        ...data,
        lastStatusUpdate: /* @__PURE__ */ new Date()
      }).where(eq(bookings.id, id)).returning();
      if (!booking) throw new Error("Booking not found");
      return booking;
    } catch (error) {
      console.error("Error in updateBooking:", error);
      throw new Error("Failed to update booking");
    }
  }
  async getBookingsByStatus(status) {
    try {
      return await db.select().from(bookings).where(eq(bookings.status, status));
    } catch (error) {
      console.error("Error in getBookingsByStatus:", error);
      throw new Error("Failed to get bookings by status");
    }
  }
  async getBookingsByDateRange(equipmentId, startDate, endDate) {
    try {
      const start = new Date(startDate);
      const end = new Date(endDate);
      if (isNaN(start.getTime()) || isNaN(end.getTime())) {
        console.error("Invalid date input:", { startDate, endDate });
        return [];
      }
      start.setUTCHours(0, 0, 0, 0);
      end.setUTCHours(23, 59, 59, 999);
      const bookingsResult = await db.select().from(bookings).where(
        and(
          eq(bookings.equipmentId, equipmentId),
          or(
            // Booking starts within the range
            and(
              gte(bookings.startDate, start),
              lte(bookings.startDate, end)
            ),
            // Booking ends within the range
            and(
              gte(bookings.endDate, start),
              lte(bookings.endDate, end)
            ),
            // Booking spans the entire range
            and(
              lte(bookings.startDate, start),
              gte(bookings.endDate, end)
            )
          )
        )
      );
      return bookingsResult.map((booking) => ({
        ...booking,
        startDate: new Date(booking.startDate),
        endDate: new Date(booking.endDate)
      }));
    } catch (error) {
      console.error("Error in getBookingsByDateRange:", error);
      return [];
    }
  }
  // Add a new method to check equipment availability directly
  async checkEquipmentAvailability(equipmentId, startDate, endDate) {
    try {
      const equipment2 = await this.getEquipment(equipmentId);
      if (!equipment2 || !equipment2.availability) {
        return false;
      }
      const existingBookings = await this.getBookingsByDateRange(equipmentId, startDate, endDate);
      const hasConflictingBooking = existingBookings.some(
        (booking) => booking.status === "paid" || booking.status === "awaiting_payment"
      );
      return !hasConflictingBooking;
    } catch (error) {
      console.error("Error checking equipment availability:", error);
      throw new Error("Failed to check equipment availability");
    }
  }
  async deleteEquipmentBookings(equipmentId) {
    try {
      await db.delete(bookings).where(eq(bookings.equipmentId, equipmentId));
      console.log(`Successfully deleted all bookings for equipment ${equipmentId}`);
    } catch (error) {
      console.error("Error deleting equipment bookings:", error);
      throw new Error("Failed to delete equipment bookings");
    }
  }
  async createReview(review) {
    try {
      const reviewData = {
        userId: review.userId,
        equipmentId: review.equipmentId,
        rating: review.rating,
        comment: review.comment,
        createdAt: /* @__PURE__ */ new Date()
      };
      const [newReview] = await db.insert(reviews).values(reviewData).returning();
      return {
        ...newReview,
        createdAt: newReview.createdAt.toISOString()
      };
    } catch (error) {
      console.error("Error creating review:", error);
      throw new Error("Failed to create review");
    }
  }
  async getReviewsByEquipment(equipmentId) {
    try {
      const results = await db.select().from(reviews).where(eq(reviews.equipmentId, equipmentId));
      return results.map((review) => ({
        ...review,
        createdAt: review.createdAt.toISOString()
      }));
    } catch (error) {
      console.error("Error in getReviewsByEquipment:", error);
      throw new Error("Failed to get reviews by equipment");
    }
  }
  async getAverageRating(equipmentId) {
    try {
      const result = await db.select({
        average: sql`COALESCE(AVG(${reviews.rating})::numeric(10,1), 0)`
      }).from(reviews).where(eq(reviews.equipmentId, equipmentId));
      return result[0]?.average || 0;
    } catch (error) {
      console.error("Error in getAverageRating:", error);
      throw new Error("Failed to get average rating");
    }
  }
  async addToComparison(userId, equipmentId) {
    try {
      const [existingComparison] = await db.select().from(comparisons).where(eq(comparisons.userId, userId));
      if (existingComparison) {
        const equipmentIds = existingComparison.equipmentIds || [];
        if (!equipmentIds.includes(equipmentId)) {
          await db.update(comparisons).set({
            equipmentIds: [...equipmentIds, equipmentId]
          }).where(eq(comparisons.userId, userId));
        }
      } else {
        await db.insert(comparisons).values({
          userId,
          equipmentIds: [equipmentId],
          createdAt: /* @__PURE__ */ new Date()
        });
      }
    } catch (error) {
      console.error("Error in addToComparison:", error);
      throw new Error("Failed to add to comparison");
    }
  }
  async removeFromComparison(userId, equipmentId) {
    try {
      const [comparison] = await db.select().from(comparisons).where(eq(comparisons.userId, userId));
      if (comparison) {
        const equipmentIds = comparison.equipmentIds.filter((id) => id !== equipmentId);
        await db.update(comparisons).set({ equipmentIds }).where(eq(comparisons.userId, userId));
      }
    } catch (error) {
      console.error("Error in removeFromComparison:", error);
      throw new Error("Failed to remove from comparison");
    }
  }
  async getComparison(userId) {
    try {
      const [comparison] = await db.select().from(comparisons).where(eq(comparisons.userId, userId));
      if (!comparison) return [];
      return await db.select().from(equipment).where(sql`${equipment.id} = ANY(${comparison.equipmentIds})`);
    } catch (error) {
      console.error("Error in getComparison:", error);
      throw new Error("Failed to get comparison");
    }
  }
  async createRecommendation(insertRecommendation) {
    try {
      const [recommendation] = await db.insert(recommendations).values({
        ...insertRecommendation,
        createdAt: /* @__PURE__ */ new Date()
      }).returning();
      return recommendation;
    } catch (error) {
      console.error("Error creating recommendation:", error);
      throw new Error("Failed to create recommendation");
    }
  }
  async getRecommendationsForUser(userId) {
    try {
      const userRecommendations = await db.select().from(recommendations).where(eq(recommendations.userId, userId)).orderBy(desc(recommendations.createdAt));
      return userRecommendations;
    } catch (error) {
      console.error("Error fetching recommendations:", error);
      throw new Error("Failed to fetch recommendations");
    }
  }
};
var storage = new DatabaseStorage();
storage.init().catch((err) => {
  console.error("Error initializing storage:", err);
});

// server/auth.ts
var scryptAsync = promisify(scrypt);
async function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");
  const buf = await scryptAsync(password, salt, 64);
  return `${buf.toString("hex")}.${salt}`;
}
async function comparePasswords(supplied, stored) {
  const [hashed, salt] = stored.split(".");
  const hashedBuf = Buffer.from(hashed, "hex");
  const suppliedBuf = await scryptAsync(supplied, salt, 64);
  return timingSafeEqual(hashedBuf, suppliedBuf);
}
function setupAuth(app2) {
  const sessionSettings = {
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: storage.sessionStore,
    cookie: {
      secure: app2.get("env") === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1e3
      // 24 hours
    }
  };
  if (app2.get("env") === "production") {
    app2.set("trust proxy", 1);
  }
  app2.use(session2(sessionSettings));
  app2.use(passport.initialize());
  app2.use(passport.session());
  app2.use((req, res, next) => {
    console.log("Session debug:", {
      isAuthenticated: req.isAuthenticated(),
      user: req.user ? { id: req.user.id, username: req.user.username } : null,
      sessionID: req.sessionID
    });
    next();
  });
  passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const user = await storage.getUserByUsername(username);
        if (!user || !await comparePasswords(password, user.password)) {
          console.log("Login failed for username:", username);
          return done(null, false);
        }
        console.log("Login successful for user:", user.id);
        return done(null, user);
      } catch (error) {
        console.error("Login error:", error);
        return done(error);
      }
    })
  );
  passport.serializeUser((user, done) => {
    console.log("Serializing user:", user.id);
    done(null, user.id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await storage.getUser(id);
      if (!user) {
        console.log("User not found during deserialization:", id);
        return done(null, false);
      }
      console.log("Deserialized user:", id);
      done(null, user);
    } catch (error) {
      console.error("Deserialization error:", error);
      done(error);
    }
  });
  app2.post("/api/register", async (req, res, next) => {
    try {
      const existingUser = await storage.getUserByUsername(req.body.username);
      if (existingUser) {
        return res.status(400).send("Username already exists");
      }
      const user = await storage.createUser({
        ...req.body,
        password: await hashPassword(req.body.password)
      });
      req.login(user, (err) => {
        if (err) return next(err);
        console.log("New user registered and logged in:", user.id);
        res.status(201).json(user);
      });
    } catch (error) {
      console.error("Registration error:", error);
      next(error);
    }
  });
  app2.post("/api/login", passport.authenticate("local"), (req, res) => {
    console.log("Login successful, sending user data");
    res.status(200).json(req.user);
  });
  app2.post("/api/logout", (req, res, next) => {
    const userId = req.user?.id;
    req.logout((err) => {
      if (err) {
        console.error("Logout error:", err);
        return next(err);
      }
      console.log("User logged out:", userId);
      res.sendStatus(200);
    });
  });
  app2.get("/api/user", (req, res) => {
    if (!req.isAuthenticated()) {
      console.log("Unauthorized access attempt to /api/user");
      return res.sendStatus(401);
    }
    console.log("User data requested:", req.user.id);
    res.json(req.user);
  });
}

// server/routes.ts
init_schema();
import multer from "multer";
import path from "path";
import { nanoid } from "nanoid";
import express from "express";
import fs from "fs";

// server/payment.ts
import Razorpay from "razorpay";
import crypto from "crypto";
if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) {
  throw new Error("RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET are required");
}
var razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});
async function createPaymentSession(bookingId, amount, equipmentName) {
  try {
    console.log("Creating payment session for booking:", bookingId, "amount:", amount);
    if (amount <= 0) {
      throw new Error("Invalid amount. Amount must be greater than 0");
    }
    const amountInPaise = Math.floor(amount * 100);
    console.log("Amount in paise:", amountInPaise);
    const orderOptions = {
      amount: amountInPaise,
      currency: "INR",
      receipt: `booking_${bookingId}`,
      notes: {
        bookingId: bookingId.toString(),
        equipmentName
      }
    };
    console.log("Creating Razorpay order with options:", orderOptions);
    const order = await razorpay.orders.create(orderOptions);
    console.log("Razorpay order created:", order);
    if (!order?.id) {
      throw new Error("Failed to create Razorpay order");
    }
    const config = {
      id: order.id,
      keyId: process.env.RAZORPAY_KEY_ID,
      amount: amountInPaise,
      currency: "INR",
      name: "AgriRent Equipment",
      description: `Booking for ${equipmentName}`,
      prefill: {
        name: "",
        // Will be filled by frontend
        email: "",
        // Will be filled by frontend
        contact: ""
        // Will be filled by frontend
      }
    };
    console.log("Returning payment configuration:", { ...config, keyId: "***" });
    return config;
  } catch (error) {
    console.error("Error creating payment session:", error);
    throw error;
  }
}
async function verifyPaymentSignature(orderId, paymentId, signature) {
  try {
    const text2 = orderId + "|" + paymentId;
    const expectedSignature = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(text2).digest("hex");
    return expectedSignature === signature;
  } catch (error) {
    console.error("Error verifying payment signature:", error);
    return false;
  }
}
async function generateReceipt(bookingId, paymentId) {
  try {
    const payment = await razorpay.payments.fetch(paymentId);
    return {
      bookingId,
      paymentId,
      status: payment.status,
      amount: Number(payment.amount) / 100,
      // Convert paise to rupees
      currency: payment.currency,
      timestamp: new Date(payment.created_at * 1e3).toISOString(),
      method: payment.method,
      receipt_url: null
      // Razorpay doesn't provide a receipt URL by default
    };
  } catch (error) {
    console.error("Error generating receipt:", error);
    throw new Error("Failed to generate receipt");
  }
}

// server/routes.ts
import crypto2 from "crypto";
var upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(process.cwd(), "uploads");
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const uniqueId = nanoid();
      const ext = path.extname(file.originalname);
      cb(null, `${uniqueId}${ext}`);
    }
  }),
  fileFilter: (req, file, cb) => {
    const allowedTypes = ["image/jpeg", "image/png", "image/webp"];
    if (!allowedTypes.includes(file.mimetype)) {
      const error = new Error("Invalid file type. Only JPEG, PNG and WebP images are allowed.");
      return cb(error, false);
    }
    cb(null, true);
  },
  limits: {
    fileSize: 5 * 1024 * 1024
    // 5MB limit
  }
});
function registerRoutes(app2) {
  const httpServer = createServer(app2);
  setupAuth(app2);
  app2.use("/uploads", express.static(path.join(process.cwd(), "uploads")));
  app2.post("/api/user/profile/image", upload.single("image"), async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    if (!req.file) return res.status(400).send("No image uploaded");
    const imageUrl = `/uploads/${req.file.filename}`;
    await storage.updateUser(req.user.id, { imageUrl });
    res.json({ imageUrl });
  });
  app2.patch("/api/user/profile", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    const parsed = updateProfileSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json(parsed.error);
    }
    const updatedUser = await storage.updateUser(req.user.id, parsed.data);
    res.json(updatedUser);
  });
  app2.get("/api/equipment", async (req, res) => {
    try {
      const owned = req.query.owned === "true";
      console.log("Fetching equipment, owned filter:", owned);
      if (owned) {
        if (!req.isAuthenticated()) {
          console.log("Unauthorized attempt to view owned equipment");
          return res.status(401).json({ error: "Authentication required to view owned equipment" });
        }
        const equipment3 = await storage.listEquipmentByOwner(req.user.id);
        console.log(`Found ${equipment3.length} items owned by user ${req.user.id}`);
        return res.json(equipment3);
      }
      const equipment2 = await storage.listEquipment();
      console.log(`Found ${equipment2.length} total equipment items`);
      equipment2.forEach((item) => {
        console.log(`Equipment ${item.id}: availability = ${item.availability}`);
      });
      res.json(equipment2);
    } catch (error) {
      console.error("Error listing equipment:", error);
      res.status(500).json({ error: "Failed to list equipment" });
    }
  });
  app2.get("/api/equipment/:id", async (req, res) => {
    try {
      const equipment2 = await storage.getEquipment(parseInt(req.params.id));
      if (!equipment2) return res.status(404).json({ error: "Equipment not found" });
      res.json(equipment2);
    } catch (error) {
      console.error("Error getting equipment:", error);
      res.status(500).json({ error: "Failed to get equipment details" });
    }
  });
  app2.post("/api/equipment", upload.single("image"), async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Authentication required" });
    }
    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Image is required",
          details: "Please upload an equipment image"
        });
      }
      let specs = {};
      let features = [];
      try {
        if (req.body.specs) {
          specs = JSON.parse(req.body.specs);
          if (typeof specs !== "object" || Array.isArray(specs)) {
            throw new Error("Specs must be an object");
          }
        }
        if (req.body.features) {
          features = JSON.parse(req.body.features);
          if (!Array.isArray(features)) {
            throw new Error("Features must be an array");
          }
        }
      } catch (error) {
        return res.status(400).json({
          error: "Invalid JSON format",
          details: error instanceof Error ? error.message : "Invalid specs or features format"
        });
      }
      const equipmentData = {
        name: req.body.name,
        description: req.body.description,
        category: req.body.category,
        dailyRate: parseInt(req.body.dailyRate),
        location: req.body.location,
        specs,
        features,
        ownerId: req.user.id,
        imageUrl: `/uploads/${req.file.filename}`
      };
      const parsed = insertEquipmentSchema.safeParse(equipmentData);
      if (!parsed.success) {
        return res.status(400).json({
          error: "Validation failed",
          details: parsed.error.errors
        });
      }
      const equipment2 = await storage.createEquipment(parsed.data);
      res.status(201).json({
        message: "Equipment created successfully",
        equipment: equipment2
      });
    } catch (error) {
      console.error("Error creating equipment:", error);
      res.status(500).json({
        error: "Failed to create equipment",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.patch("/api/equipment/:id", upload.single("image"), async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Authentication required" });
    }
    try {
      const equipmentId = parseInt(req.params.id);
      const equipment2 = await storage.getEquipment(equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      if (equipment2.ownerId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Not authorized to update this equipment" });
      }
      let updateData = {
        ...req.body
      };
      if (req.file) {
        updateData.imageUrl = `/uploads/${req.file.filename}`;
      }
      if (req.body.specs) {
        try {
          updateData.specs = JSON.parse(req.body.specs);
        } catch (e) {
          return res.status(400).json({ error: "Invalid specs format" });
        }
      }
      if (req.body.features) {
        try {
          updateData.features = JSON.parse(req.body.features);
        } catch (e) {
          return res.status(400).json({ error: "Invalid features format" });
        }
      }
      if (req.body.dailyRate) {
        updateData.dailyRate = parseInt(req.body.dailyRate);
      }
      const updated = await storage.updateEquipment(equipmentId, updateData);
      res.json(updated);
    } catch (error) {
      console.error("Error updating equipment:", error);
      res.status(500).json({
        error: "Failed to update equipment",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/equipment/:id/availability", async (req, res) => {
    try {
      const equipmentId = parseInt(req.params.id);
      if (isNaN(equipmentId)) {
        console.error("Invalid equipment ID:", req.params.id);
        return res.status(400).json({ error: "Invalid equipment ID" });
      }
      const now = /* @__PURE__ */ new Date();
      let startDate = now;
      let endDate = new Date(now);
      endDate.setDate(endDate.getDate() + 30);
      if (req.query.startDate) {
        const parsedStart = new Date(req.query.startDate);
        if (!isNaN(parsedStart.getTime())) {
          startDate = parsedStart;
        } else {
          console.error("Invalid start date:", req.query.startDate);
          return res.status(400).json({ error: "Invalid start date format" });
        }
      }
      if (req.query.endDate) {
        const parsedEnd = new Date(req.query.endDate);
        if (!isNaN(parsedEnd.getTime())) {
          endDate = parsedEnd;
        } else {
          console.error("Invalid end date:", req.query.endDate);
          return res.status(400).json({ error: "Invalid end date format" });
        }
      }
      if (startDate < now) {
        startDate = now;
      }
      if (endDate <= startDate) {
        endDate = new Date(startDate);
        endDate.setDate(startDate.getDate() + 30);
      }
      const equipment2 = await storage.getEquipment(equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      if (!equipment2.availability) {
        return res.json({
          available: false,
          message: "Equipment is not available for booking"
        });
      }
      const isAvailable = await storage.checkEquipmentAvailability(
        equipmentId,
        startDate,
        endDate
      );
      res.json({
        available: isAvailable,
        startDate: startDate.toISOString(),
        endDate: endDate.toISOString(),
        message: isAvailable ? "Equipment is available for the selected dates" : "Equipment is not available for the selected dates"
      });
    } catch (error) {
      console.error("Error checking equipment availability:", error);
      res.status(500).json({
        error: "Failed to check equipment availability",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.patch("/api/equipment/:id/availability", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const equipmentId = parseInt(req.params.id);
      const equipment2 = await storage.getEquipment(equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      if (equipment2.ownerId !== req.user.id) {
        return res.status(403).json({ error: "Not authorized to update this equipment" });
      }
      const { available } = req.body;
      const updated = await storage.updateEquipment(equipmentId, {
        availability: available
      });
      res.json(updated);
    } catch (error) {
      console.error("Error updating availability:", error);
      res.status(500).json({ error: "Failed to update availability" });
    }
  });
  app2.delete("/api/equipment/:id", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Authentication required" });
    }
    try {
      const equipmentId = parseInt(req.params.id);
      const equipment2 = await storage.getEquipment(equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      if (equipment2.ownerId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Not authorized to delete this equipment" });
      }
      await storage.deleteEquipment(equipmentId);
      await storage.deleteEquipmentBookings(equipmentId);
      res.json({ success: true, message: "Equipment deleted successfully" });
    } catch (error) {
      console.error("Error deleting equipment:", error);
      res.status(500).json({
        error: "Failed to delete equipment",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/bookings", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const bookingData = {
        ...req.body,
        userId: req.user.id,
        status: "pending"
      };
      const parsed = insertBookingSchema.safeParse(bookingData);
      if (!parsed.success) {
        return res.status(400).json({
          error: "Invalid booking data",
          details: parsed.error.errors
        });
      }
      const equipment2 = await storage.getEquipment(parsed.data.equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      if (!equipment2.availability) {
        return res.status(400).json({ error: "Equipment is not available for booking" });
      }
      const startDate = new Date(parsed.data.startDate);
      const endDate = new Date(parsed.data.endDate);
      const totalDays = Math.max(1, Math.ceil(
        (endDate.getTime() - startDate.getTime()) / (1e3 * 3600 * 24)
      ) + 1);
      const totalAmount = equipment2.dailyRate * totalDays;
      const isAvailable = await storage.checkEquipmentAvailability(
        parsed.data.equipmentId,
        startDate,
        endDate
      );
      if (!isAvailable) {
        return res.status(400).json({ error: "Equipment is no longer available for these dates" });
      }
      const booking = await storage.createBooking({
        ...parsed.data,
        totalPrice: totalAmount,
        startDate,
        endDate,
        status: "pending"
      });
      try {
        await storage.updateEquipment(parsed.data.equipmentId, {
          availability: false
        });
        const razorpayOrder = await createPaymentSession(booking.id, totalAmount, equipment2.name);
        const updatedBooking = await storage.updateBooking(booking.id, {
          status: "awaiting_payment",
          razorpayOrderId: razorpayOrder.id
        });
        console.log(`Created booking ${booking.id} for equipment ${equipment2.id}, awaiting payment`);
        res.status(201).json({
          booking: updatedBooking,
          razorpayConfig: {
            key: razorpayOrder.keyId,
            amount: razorpayOrder.amount,
            currency: razorpayOrder.currency,
            name: razorpayOrder.name,
            description: razorpayOrder.description,
            order_id: razorpayOrder.id,
            prefill: razorpayOrder.prefill
          }
        });
      } catch (paymentError) {
        console.error("Error in payment order creation:", paymentError);
        await storage.updateEquipment(parsed.data.equipmentId, {
          availability: true
        });
        await storage.updateBooking(booking.id, { status: "payment_failed" });
        res.status(400).json({
          error: "Payment order creation failed",
          details: paymentError instanceof Error ? paymentError.message : "Unknown payment error"
        });
      }
    } catch (error) {
      console.error("Error in booking creation:", error);
      res.status(500).json({
        error: "Failed to process booking",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/bookings/verify-payment", express.json(), async (req, res) => {
    try {
      const { bookingId, razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
      if (!bookingId || !razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
        console.error("Missing required payment verification fields:", req.body);
        return res.status(400).json({
          error: "Missing required payment details",
          details: "All payment verification fields are required"
        });
      }
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        console.error(`Booking not found for verification: ${bookingId}`);
        return res.status(404).json({ error: "Booking not found" });
      }
      if (booking.status === "paid") {
        console.log(`Payment already verified for booking ${bookingId}`);
        return res.status(200).json({ success: true, booking });
      }
      const isValid = await verifyPaymentSignature(razorpay_order_id, razorpay_payment_id, razorpay_signature);
      if (!isValid) {
        console.error("Invalid payment signature for booking:", bookingId);
        await storage.updateEquipment(booking.equipmentId, {
          availability: true
        });
        return res.status(400).json({ error: "Invalid payment signature" });
      }
      console.log(`Processing payment verification for booking ${bookingId}, equipment ${booking.equipmentId}`);
      const updatedBooking = await storage.updateBooking(bookingId, {
        status: "paid",
        razorpayPaymentId: razorpay_payment_id
      });
      if (!updatedBooking) {
        throw new Error("Failed to update booking status");
      }
      console.log(`Successfully updated booking ${bookingId} status to paid`);
      await storage.updateEquipment(booking.equipmentId, {
        availability: false
      });
      console.log(`Equipment ${booking.equipmentId} marked as unavailable after payment verification`);
      res.json({
        success: true,
        booking: updatedBooking,
        message: "Payment verified successfully and equipment marked as unavailable"
      });
    } catch (error) {
      console.error("Payment verification error:", error);
      res.status(500).json({
        error: "Payment verification failed",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/webhooks/razorpay", express.raw({ type: "application/json" }), async (req, res) => {
    try {
      const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET;
      if (webhookSecret) {
        const signature = req.headers["x-razorpay-signature"];
        if (!signature) {
          return res.status(400).json({ error: "Missing signature" });
        }
        const expectedSignature = crypto2.createHmac("sha256", webhookSecret).update(req.body).digest("hex");
        if (signature !== expectedSignature) {
          return res.status(400).json({ error: "Invalid signature" });
        }
      }
      const event = JSON.parse(req.body.toString());
      const result = await handleWebhookEvent(event);
      if (result) {
        if (result.status === "success" && result.paymentId) {
          const booking = await storage.updateBooking(result.bookingId, {
            status: "paid",
            razorpayPaymentId: result.paymentId
          });
          if (booking) {
            await storage.updateEquipment(booking.equipmentId, {
              availability: false
            });
            await generateReceipt(result.bookingId, result.paymentId);
          }
        } else if (result.status === "failed") {
          const booking = await storage.updateBooking(result.bookingId, {
            status: "payment_failed"
          });
          if (booking) {
            await storage.updateEquipment(booking.equipmentId, {
              availability: true
            });
          }
        }
      }
      res.json({ received: true });
    } catch (err) {
      console.error("Webhook Error:", err);
      if (err instanceof Error) {
        res.status(400).send(`Webhook Error: ${err.message}`);
      } else {
        res.status(400).send("Webhook Error: Unknown error");
      }
    }
  });
  app2.post("/api/bookings/:id/receipt", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const bookingId = parseInt(req.params.id);
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      if (!booking.razorpayPaymentId) {
        return res.status(400).json({ error: "No payment found for this booking" });
      }
      const receipt = await generateReceipt(bookingId, booking.razorpayPaymentId);
      res.json(receipt);
    } catch (error) {
      console.error("Error generating receipt:", error);
      res.status(500).json({ error: "Failed to generate receipt" });
    }
  });
  app2.get("/api/equipment/:id/reviews", async (req, res) => {
    try {
      const equipmentId = parseInt(req.params.id);
      if (isNaN(equipmentId)) {
        return res.status(400).json({ error: "Invalid equipment ID" });
      }
      const reviews2 = await storage.getReviewsByEquipment(equipmentId);
      console.log(`Fetched ${reviews2.length} reviews for equipment ${equipmentId}`);
      res.json(reviews2);
    } catch (error) {
      console.error("Error fetching reviews:", error);
      res.status(500).json({
        error: "Failed to fetch reviews",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.post("/api/reviews", async (req, res) => {
    if (!req.isAuthenticated()) {
      return res.status(401).json({ error: "Authentication required" });
    }
    try {
      const reviewData = {
        ...req.body,
        userId: req.user.id,
        createdAt: /* @__PURE__ */ new Date()
      };
      const validationResult = reviewSchema.safeParse(reviewData);
      if (!validationResult.success) {
        return res.status(400).json({
          error: "Invalid review data",
          details: validationResult.error.errors
        });
      }
      const bookings2 = await storage.listBookings(req.user.id);
      const validBooking = bookings2.find(
        (b) => b.equipmentId === reviewData.equipmentId && b.status === "paid" && !b.isRated
      );
      if (!validBooking) {
        return res.status(400).json({
          error: "Invalid review submission",
          details: "You can only review equipment from paid, unrated bookings"
        });
      }
      const newReview = await storage.createReview(validationResult.data);
      console.log(`Created new review for equipment ${reviewData.equipmentId} by user ${req.user.id}`);
      await storage.updateBooking(validBooking.id, { isRated: true });
      console.log(`Updated booking ${validBooking.id} as rated`);
      res.json(newReview);
    } catch (error) {
      console.error("Error creating review:", error);
      res.status(500).json({
        error: "Failed to create review",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/bookings", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const bookings2 = req.user.isAdmin ? await storage.listBookings() : await storage.listBookings(req.user.id);
      const bookingsWithUserInfo = await Promise.all(
        bookings2.map(async (booking) => {
          if (req.user.isAdmin && booking.userId !== req.user.id) {
            const bookingUser = await storage.getUser(booking.userId);
            return {
              ...booking,
              userInfo: bookingUser ? {
                username: bookingUser.username,
                name: bookingUser.name
              } : null
            };
          }
          return booking;
        })
      );
      res.json(bookingsWithUserInfo);
    } catch (error) {
      console.error("Error fetching bookings:", error);
      res.status(500).json({
        error: "Failed to fetch bookings",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/bookings/:id/status", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const bookingId = parseInt(req.params.id);
      if (isNaN(bookingId)) {
        return res.status(400).json({ error: "Invalid booking ID" });
      }
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      if (booking.userId !== req.user.id && !req.user.isAdmin) {
        return res.status(403).json({ error: "Not authorized" });
      }
      res.json({
        id: booking.id,
        status: booking.status,
        razorpayOrderId: booking.razorpayOrderId,
        totalPrice: booking.totalPrice,
        equipmentId: booking.equipmentId,
        startDate: booking.startDate,
        endDate: booking.endDate
      });
    } catch (error) {
      console.error("Error checking booking status:", error);
      res.status(500).json({ error: "Failed to check booking status" });
    }
  });
  app2.patch("/api/bookings/:id/status", async (req, res) => {
    if (!req.isAuthenticated() || !req.user.isAdmin) return res.sendStatus(401);
    try {
      const bookingId = parseInt(req.params.id);
      if (isNaN(bookingId)) {
        return res.status(400).json({ error: "Invalid booking ID" });
      }
      const { status } = req.body;
      if (!status || !["approved", "rejected"].includes(status)) {
        return res.status(400).json({ error: "Invalid status" });
      }
      const updatedBooking = await storage.updateBookingStatus(bookingId, status);
      res.json(updatedBooking);
    } catch (error) {
      console.error("Error updating booking status:", error);
      res.status(500).json({ error: "Failed to update booking status" });
    }
  });
  app2.get("/api/bookings/:id/payment-config", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);
    try {
      const bookingId = parseInt(req.params.id);
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        return res.status(404).json({ error: "Booking not found" });
      }
      if (booking.userId !== req.user.id) {
        return res.status(403).json({ error: "Not authorized to access this booking" });
      }
      const equipment2 = await storage.getEquipment(booking.equipmentId);
      if (!equipment2) {
        return res.status(404).json({ error: "Equipment not found" });
      }
      const config = await createPaymentSession(bookingId, booking.totalPrice, equipment2.name);
      res.json(config);
    } catch (error) {
      console.error("Error getting payment configuration:", error);
      res.status(500).json({
        error: "Failed to get payment configuration",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  app2.get("/api/bookings/:id", async (req, res) => {
    if (!req.isAuthenticated()) {
      console.log("Unauthorized attempt to access booking:", req.params.id);
      return res.status(401).json({ error: "Authentication required" });
    }
    try {
      const bookingId = parseInt(req.params.id);
      if (isNaN(bookingId)) {
        console.error("Invalid booking ID:", req.params.id);
        return res.status(400).json({ error: "Invalid booking ID" });
      }
      console.log(`Looking up booking ${bookingId} for user ${req.user.id}`);
      const booking = await storage.getBooking(bookingId);
      if (!booking) {
        console.log(`Booking ${bookingId} not found`);
        return res.status(404).json({ error: "Booking not found" });
      }
      if (booking.userId !== req.user.id && !req.user.isAdmin) {
        console.log(`User ${req.user.id} not authorized to view booking ${bookingId}`);
        return res.status(403).json({ error: "Not authorized to view this booking" });
      }
      console.log(`Successfully retrieved booking ${bookingId}`);
      res.json(booking);
    } catch (error) {
      console.error("Error getting booking:", error);
      res.status(500).json({ error: "Failed to get bookingdetails" });
    }
  });
  app2.post("/api/comparisons/comparisons/add/:equipmentId", async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.sendStatus(401);
    }
    try {
      const equipmentId = parseInt(req.params.equipmentId);
      await storage.addToComparison(req.user.id, equipmentId);
      res.sendStatus(200);
    } catch (error) {
      console.error("Error adding to comparison:", error);
      res.status(500).json({ error: "Failed to add to comparison" });
    }
  });
  app2.delete("/api/comparisons/remove/:equipmentId", async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.sendStatus(401);
    }
    try {
      const equipmentId = parseInt(req.params.equipmentId);
      await storage.removeFromComparison(req.user.id, equipmentId);
      res.sendStatus(200);
    } catch (error) {
      console.error("Error removing from comparison:", error);
      res.status(500).json({ error: "Failed to remove from comparison" });
    }
  });
  app2.get("/api/comparisons", async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.sendStatus(401);
    }
    try {
      const equipment2 = await storage.getComparison(req.user.id);
      res.json(equipment2);
    } catch (error) {
      console.error("Error fetching comparison:", error);
      res.status(500).json({ error: "Failed to fetch comparison" });
    }
  });
  app2.get("/api/recommendations", async (req, res) => {
    if (!req.isAuthenticated() || !req.user) {
      return res.sendStatus(401);
    }
    try {
      const user = await storage.getUser(req.user.id);
      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }
      const userBookings = await storage.listBookings(user.id);
      const allEquipment = await storage.listEquipment();
      const recommendations2 = allEquipment.map((equipment2) => {
        let score = 0;
        let reasons = [];
        if (user.preferences.preferredCategories.includes(equipment2.category)) {
          score += 30;
          reasons.push(`Matches your preferred category: ${equipment2.category}`);
        }
        if (user.preferences.preferredLocations.includes(equipment2.location)) {
          score += 20;
          reasons.push(`Available in your preferred location: ${equipment2.location}`);
        }
        if (equipment2.dailyRate >= user.preferences.priceRange.min && equipment2.dailyRate <= user.preferences.priceRange.max) {
          score += 15;
          reasons.push("Within your preferred price range");
        }
        const matchingFeatures = equipment2.features.filter(
          (feature) => user.preferences.features.includes(feature)
        );
        if (matchingFeatures.length > 0) {
          score += 5 * matchingFeatures.length;
          reasons.push(`Has ${matchingFeatures.length} features you prefer`);
        }
        if (equipment2.popularity > 0) {
          score += Math.min(10, equipment2.popularity);
        }
        if (userBookings.some((booking) => booking.equipmentId === equipment2.id)) {
          score += 10;
          reasons.push("You have rented this before");
        }
        return {
          equipment: equipment2,
          score: Math.min(100, score),
          // Cap at 100%
          reason: reasons[0] || "Recommended based on your preferences"
        };
      });
      const topRecommendations = recommendations2.filter((rec) => rec.score > 30).sort((a, b) => b.score - a.score).slice(0, 5);
      await Promise.all(topRecommendations.map(async (rec) => {
        await storage.createRecommendation({
          userId: user.id,
          equipmentId: rec.equipment.id,
          score: rec.score,
          reason: rec.reason
        });
      }));
      res.json(topRecommendations);
    } catch (error) {
      console.error("Error generating recommendations:", error);
      res.status(500).json({
        error: "Failed to generate recommendations",
        details: error instanceof Error ? error.message : "Unknown error"
      });
    }
  });
  return httpServer;
}
async function handleWebhookEvent(event) {
  console.log("Webhook event received:", event);
  if (event.payload.payment.status === "captured") {
    return { status: "success", bookingId: event.payload.payment.order_id, paymentId: event.payload.payment.id };
  } else if (event.payload.payment.status === "failed") {
    return { status: "failed", bookingId: event.payload.payment.order_id };
  }
  return null;
}

// server/vite.ts
import express2 from "express";
import fs2 from "fs";
import path3, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path2, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  plugins: [react(), runtimeErrorOverlay(), themePlugin()],
  resolve: {
    alias: {
      "@": path2.resolve(__dirname, "client", "src"),
      "@shared": path2.resolve(__dirname, "shared")
    }
  },
  root: path2.resolve(__dirname, "client"),
  build: {
    outDir: path2.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid as nanoid2 } from "nanoid";
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
function log(message, source = "express") {
  const formattedTime = (/* @__PURE__ */ new Date()).toLocaleTimeString("en-US", {
    hour: "numeric",
    minute: "2-digit",
    second: "2-digit",
    hour12: true
  });
  console.log(`${formattedTime} [${source}] ${message}`);
}
async function setupVite(app2, server) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options) => {
        viteLogger.error(msg, options);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path3.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid2()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path3.resolve(__dirname2, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express2.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path3.resolve(distPath, "index.html"));
  });
}

// server/index.ts
import fs3 from "fs";
import path4 from "path";

// server/migrations.ts
init_db();
async function createTables() {
  try {
    console.log("Creating database tables...");
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT false,
        name TEXT NOT NULL,
        contact TEXT,
        language TEXT NOT NULL DEFAULT 'en',
        image_url TEXT,
        preferences JSONB NOT NULL DEFAULT '{"preferredCategories": [], "preferredLocations": [], "priceRange": {"min": 0, "max": 100000}, "features": []}'
      );

      CREATE TABLE IF NOT EXISTS equipment (
        id SERIAL PRIMARY KEY,
        owner_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        daily_rate INTEGER NOT NULL,
        image_url TEXT NOT NULL,
        location TEXT NOT NULL,
        availability BOOLEAN NOT NULL DEFAULT true,
        specs JSONB NOT NULL DEFAULT '{}',
        features JSONB NOT NULL DEFAULT '[]',
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        popularity INTEGER NOT NULL DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS bookings (
        id SERIAL PRIMARY KEY,
        equipment_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        start_date TIMESTAMP NOT NULL,
        end_date TIMESTAMP NOT NULL,
        total_price INTEGER NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        razorpay_order_id TEXT,
        razorpay_payment_id TEXT,
        is_rated BOOLEAN NOT NULL DEFAULT false,
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        last_status_update TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS reviews (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        equipment_id INTEGER NOT NULL,
        rating INTEGER NOT NULL,
        comment TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS comparisons (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        equipment_ids INTEGER[] NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS recommendations (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        equipment_id INTEGER NOT NULL,
        score INTEGER NOT NULL,
        reason TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
      );
    `);
    console.log("Database tables created successfully");
  } catch (error) {
    console.error("Error creating tables:", error);
    throw error;
  }
}
createTables().catch(console.error);

// server/index.ts
var uploadsDir = path4.join(process.cwd(), "uploads");
if (!fs3.existsSync(uploadsDir)) {
  fs3.mkdirSync(uploadsDir, { recursive: true });
}
var app = express3();
app.use(express3.json());
app.use(express3.urlencoded({ extended: false }));
app.use((req, res, next) => {
  const start = Date.now();
  const path5 = req.path;
  let capturedJsonResponse = void 0;
  const originalResJson = res.json;
  res.json = function(bodyJson, ...args) {
    try {
      capturedJsonResponse = bodyJson;
      return originalResJson.apply(res, [bodyJson, ...args]);
    } catch (error) {
      console.error("Error in JSON response:", error);
      return originalResJson.apply(res, [{ error: "Internal Server Error" }]);
    }
  };
  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path5.startsWith("/api")) {
      let logLine = `${req.method} ${path5} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        try {
          logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
        } catch (error) {
          logLine += " :: [Error serializing response]";
        }
      }
      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "\u2026";
      }
      log(logLine);
    }
  });
  next();
});
async function findAvailablePort(startPort, maxTries = 10) {
  const net = await import("net");
  for (let port = startPort; port < startPort + maxTries; port++) {
    try {
      const server = net.createServer();
      await new Promise((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "0.0.0.0", () => {
          server.once("close", resolve);
          server.close();
        });
      });
      return port;
    } catch (err) {
      console.error(`Port ${port} is not available:`, err);
      if (port === startPort + maxTries - 1) {
        throw new Error("No available ports found");
      }
      continue;
    }
  }
  throw new Error("No available ports found");
}
createTables().catch((err) => {
  console.error("Failed to create database tables:", err);
  process.exit(1);
});
(async () => {
  try {
    const server = registerRoutes(app);
    server.keepAliveTimeout = 12e4;
    server.headersTimeout = 121e3;
    server.timeout = 18e4;
    app.use((err, _req, res, _next) => {
      const status = err.status || err.statusCode || 500;
      const message = err.message || "Internal Server Error";
      console.error("Error:", {
        status,
        message,
        stack: err.stack,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
      res.status(status).json({
        message,
        status,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      });
    });
    if (app.get("env") === "development") {
      await setupVite(app, server);
    } else {
      serveStatic(app);
    }
    const preferredPort = Number(process.env.PORT) || 5e3;
    const port = await findAvailablePort(preferredPort);
    server.on("connection", (socket) => {
      socket.setKeepAlive(true, 3e4);
      socket.setTimeout(12e4);
      socket.on("error", (err) => {
        console.error("Socket error:", err);
      });
      socket.on("timeout", () => {
        console.log("Socket timeout detected");
        socket.end();
      });
    });
    server.listen(port, "0.0.0.0", () => {
      log(`Server ready and listening on port ${port}`);
      if (process.send) {
        process.send("ready");
      }
    });
    const cleanup = async () => {
      console.log("Initiating graceful shutdown...");
      await new Promise((resolve) => {
        server.close(() => {
          console.log("Server closed");
          resolve();
        });
      });
      try {
        const { pool: pool2 } = (init_db(), __toCommonJS(db_exports));
        await pool2.end();
        console.log("Database pool closed");
      } catch (error) {
        console.error("Error closing database pool:", error);
      }
      process.exit(0);
    };
    process.on("SIGTERM", cleanup);
    process.on("SIGINT", cleanup);
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
})();
