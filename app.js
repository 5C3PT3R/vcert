import express from "express";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";


dotenv.config();

const app = express();
// cors disabled for simplicity
import cors from "cors";
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

const port = process.env.PORT || 3000;

const client = new Client(process.env.DATABASE_URL);
const upload = multer({
    dest: "uploads/",
    fileFilter: (req, file, cb) => {
        if (file.mimetype === "application/pdf") {
            cb(null, true);
        } else {
            cb(new Error("Only PDF files are allowed"));
        }
    }
});
const secretKey = process.env.JWT_SECRET || "super_secret_key";

app.use(express.json());

// Middleware for authentication
const authenticate = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(401).send("Unauthorized");

    try {
        const decoded = jwt.verify(token, secretKey);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(401).send("Invalid token");
    }
};

(async () => {
    await client.connect();
    console.log("Connected to the database");

    app.get("/", async (req, res) => {
        try {
            const results = await client.query("SELECT NOW()");
            res.json({ time: results.rows[0] });
        } catch (err) {
            console.error("Error executing query:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // Register route
    app.post("/register", async (req, res) => {
        const { email, username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);

        try {
            await client.query(
                "INSERT INTO users (email, username, pass_hash) VALUES ($1, $2, $3)",
                [email, username, hashedPassword]
            );
            res.status(201).send("User registered");
        } catch (err) {
            console.error("Error registering user:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // Login route
    app.post("/login", async (req, res) => {
        const { identifier, password } = req.body; // 'identifier' can be either email or username

        try {
            const result = await client.query(
                "SELECT * FROM users WHERE email = $1 OR username = $1",
                [identifier]
            );
            const user = result.rows[0];

            if (user && (await bcrypt.compare(password, user.pass_hash))) {
                const token = jwt.sign({ id: user.id, email: user.email }, secretKey, { expiresIn: "1h" });
                res.json({ token });
            } else {
                res.status(401).send("Invalid credentials");
            }
        } catch (err) {
            console.error("Error logging in:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // Upload certificates route
    app.post("/upload", authenticate, upload.array("certificates", 10), async (req, res) => {
        const files = req.files;
        const responses = [];

        try {
            for (const file of files) {
                const fileBuffer = fs.readFileSync(file.path);
                const hash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
                const newPath = `uploads/${hash}.pdf`;

                fs.renameSync(file.path, newPath);
                await client.query(
                    "INSERT INTO cert (user_key, hash, serial) VALUES ($1, $2, $3)",
                    [req.user.id, hash, hash.slice(0, 4).toUpperCase()]
                );
                responses.push({ serial: hash.slice(0, 4).toUpperCase() });
            }

            res.status(201).send(responses);
        } catch (err) {
            console.error("Error uploading certificates:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // List certificates route
    app.get("/certificates", authenticate, async (req, res) => {
        try {
            const result = await client.query("SELECT serial FROM cert WHERE user_key = $1", [req.user.id]);
            // console.log(result.rows);
            res.json(result.rows);
        } catch (err) {
            console.error("Error fetching certificates:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // Retrieve certificate route
    app.get("/retrieve", authenticate, async (req, res) => {
        const { serial } = req.query;
        console.log("____________");
        console.log(req.user);
        console.log("____________");

        try {
            const result = await client.query(
                "SELECT hash FROM cert WHERE serial = $1 AND user_key = $2",
                [serial, req.user.id]
            );
            const cert = result.rows[0];

            if (cert) {
                const filePath = path.resolve(`uploads/${cert.hash}.pdf`);
                if (fs.existsSync(filePath)) {
                    res.download(filePath);
                } else {
                    res.status(404).send("Certificate file not found on server");
                }
            } else {
                res.status(404).send("Certificate not found in database");
            }
        } catch (err) {
            console.error("Error retrieving certificate:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    // Delete certificate route
    app.delete("/delete", authenticate, async (req, res) => {
        const { serial } = req.query; // Updated to use query parameters instead of body

        try {
            const result = await client.query("SELECT hash FROM cert WHERE serial = $1 AND user_key = $2", [serial, req.user.id]);
            const cert = result.rows[0];

            if (cert) {
                const filePath = path.resolve(`uploads/${cert.hash}.pdf`);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }

                await client.query("DELETE FROM cert WHERE serial = $1 AND user_key = $2", [serial, req.user.id]);
                res.status(200).send("Certificate deleted successfully");
            } else {
                res.status(404).send("Certificate not found");
            }
        } catch (err) {
            console.error("Error deleting certificate:", err);
            res.status(500).send("Internal Server Error");
        }
    });

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
})();