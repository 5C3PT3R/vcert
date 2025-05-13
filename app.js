import express from "express";
import { Client } from "pg";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

const client = new Client(process.env.DATABASE_URL);

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

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
})();