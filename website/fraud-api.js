import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import geolib from 'geolib';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';
import twilio from 'twilio';

dotenv.config();

const app = express();
const port = 3001;

// MongoDB setup (with fallback)
let client, db, collection, blacklistCollection;
let mongoConnected = false;

try {
    client = new MongoClient(process.env.MONGO_URI || 'mongodb://localhost:27017');
    db = client.db(process.env.MONGO_DB_NAME || 'fraud_detection');
    collection = db.collection(process.env.MONGO_COLLECTION_NAME || 'transactions');
    blacklistCollection = db.collection("blacklist");
    mongoConnected = true;
} catch (error) {
    console.log('MongoDB not available, running in memory mode');
    mongoConnected = false;
}

// In-memory blacklist for testing without MongoDB
const inMemoryBlacklist = new Set(["9876543210", "1111222233"]);

// Location coordinates
const locationLookup = {
    "Chennai": { latitude: 13.0827, longitude: 80.2707 },
    "Mumbai": { latitude: 19.0760, longitude: 72.8777 },
    "Delhi": { latitude: 28.6139, longitude: 77.2090 },
    "Bangalore": { latitude: 12.9716, longitude: 77.5946 },
};

// Track last known locations
const lastKnownLocation = {};

// Blacklisted IPs
const BLACKLISTED_IPS = new Set(["203.0.113.5", "198.51.100.10", "45.33.32.156"]);

// Transaction details array
var transaction_details = [];

// Twilio client
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// SMS sending function
async function sendSMS(phone, message) {
    try {
        console.log(`Attempting to send SMS to: ${phone}`);
        console.log(`From: ${process.env.TWILIO_NUMBER}`);
        console.log(`Message: ${message}`);
        
        const msg = await twilioClient.messages.create({
            body: message,
            from: process.env.TWILIO_NUMBER,
            to: phone
        });
        console.log(`✅ SMS sent successfully: ${msg.sid}`);
        return { success: true, sid: msg.sid };
    } catch (error) {
        console.error('❌ SMS sending failed:', error.message);
        console.error('Error code:', error.code);
        
        // For testing: simulate successful SMS when Twilio number is invalid
        if (error.code === 21659 || error.code === 21212) {
            console.log('📱 SIMULATED SMS (Twilio number invalid):');
            console.log(`To: ${phone}`);
            console.log(`Message: ${message}`);
            return { success: true, sid: 'SIMULATED_' + Date.now(), simulated: true };
        }
        
        return { success: false, error: error.message, code: error.code };
    }
}

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());

// Fraud detection functions
function detectBehavioralAnomaly(pastTxns, currentAmount, windowSize = 5, zThresh = 2.5) {
    const amounts = pastTxns.slice(-windowSize).map(txn => txn.amount);
    if (amounts.length < 2) return false;
    
    const mean = amounts.reduce((a, b) => a + b) / amounts.length;
    const variance = amounts.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / amounts.length;
    const std = Math.sqrt(variance);
    
    const zScore = std !== 0 ? Math.abs((currentAmount - mean) / std) : 0;
    return zScore > zThresh;
}

function detectGeoDrift(cardType, currentLocation, maxKm = 500) {
    if (!locationLookup[currentLocation]) return false;
    
    const lastLocation = lastKnownLocation[cardType];
    if (!lastLocation || !locationLookup[lastLocation]) return false;
    
    const distance = geolib.getDistance(
        locationLookup[lastLocation],
        locationLookup[currentLocation]
    ) / 1000; // Convert to km
    
    return distance > maxKm;
}

function getClientIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) return forwarded.split(',')[0].trim();
    return req.connection.remoteAddress || req.socket.remoteAddress;
}
// Get request to check anomalous status and send SMS
app.get("/anomalous", async (req, res) => {
  const lastTransaction = transaction_details[transaction_details.length - 1];
  const isAnomalous = lastTransaction ? lastTransaction.anomalous : false;
  
  // Send SMS notification when checking anomalous status
  if (lastTransaction) {
    const smsMessage = isAnomalous ? 
      `⚠️ FRAUD ALERT!\nTransaction ID: ${lastTransaction.transaction_id}\nAmount: ${lastTransaction.currency} ${lastTransaction.amount}\nLocation: ${lastTransaction.location}\nReasons: ${lastTransaction.fraud_reasons.join(', ')}\nTime: ${lastTransaction.timestamp}\nIf this wasn't you, contact us immediately!` :
      `✅ Transaction Approved\nID: ${lastTransaction.transaction_id}\nAmount: ${lastTransaction.currency} ${lastTransaction.amount}\nLocation: ${lastTransaction.location}\nTime: ${lastTransaction.timestamp}`;
    
    await sendSMS(lastTransaction.phone, smsMessage);
  }
  
  res.json(isAnomalous);
  console.log("Anomalous: " + isAnomalous);
});

app.get("/data", (req, res) => {
  res.json(transaction_details);
  console.log("Transaction details: " + transaction_details);
});

// Route to send SMS manually
app.post("/send-sms", async (req, res) => {
  const { phone, message } = req.body;

  if (!phone || !message) {
    return res.status(400).json({ error: "Phone and message are required" });
  }

  const result = await sendSMS(phone, message);
  
  if (result.success) {
    res.json({ status: "success", sid: result.sid });
  } else {
    res.status(500).json({ status: "error", message: result.error });
  }
});

app.post("/submit", async (req, res) => {
    try {
        const now = new Date();
        const clientIP = getClientIP(req);
        let reasons = [];
        let isAnomaly = false;

        // Check blacklisted IP
        if (BLACKLISTED_IPS.has(clientIP)) {
            reasons.push(`Blacklisted IP: ${clientIP}`);
            isAnomaly = true;
        }

        // Check blacklisted recipient account
        let blacklistedAccount = false;
        if (mongoConnected) {
            blacklistedAccount = await blacklistCollection.findOne({
                type: "account",
                value: req.body.recipient_account_number
            });
        } else {
            blacklistedAccount = inMemoryBlacklist.has(req.body.recipient_account_number);
        }
        
        if (blacklistedAccount) {
            reasons.push(`Blacklisted Recipient: ${req.body.recipient_account_number}`);
            isAnomaly = true;
        }

        // Odd hour check (12 AM to 4 AM)
        if (now.getHours() >= 0 && now.getHours() < 4) {
            reasons.push("Transaction During Odd Hours (12 AM - 4 AM)");
            isAnomaly = true;
        }

        // Get past transactions for behavioral analysis
        let pastTxns = [];
        if (mongoConnected) {
            pastTxns = await collection.find({ card_type: req.body.card_type })
                .sort({ timestamp: 1 }).toArray();
        } else {
            pastTxns = transaction_details.filter(txn => txn.card_type === req.body.card_type);
        }

        // Behavioral anomaly detection
        if (detectBehavioralAnomaly(pastTxns, parseFloat(req.body.amount))) {
            reasons.push("Abnormal Amount (Behavioral)");
            isAnomaly = true;
        }

        // Geo drift detection
        if (detectGeoDrift(req.body.card_type, req.body.location)) {
            reasons.push("Geo Drift Detected");
            isAnomaly = true;
        }

        // Update last known location if not anomalous
        if (!isAnomaly) {
            lastKnownLocation[req.body.card_type] = req.body.location;
        }

        const data = {
            amount: parseFloat(req.body.amount),
            location: req.body.location,
            card_type: req.body.card_type,
            currency: req.body.currency,
            recipient_account_number: req.body.recipient_account_number,
            sender_account_number: req.body.sender_account_number,
            transaction_id: req.body.transaction_id,
            timestamp: now,
            client_ip: clientIP,
            anomalous: isAnomaly,
            fraud_reasons: reasons
        };

        // Store in MongoDB (if available)
        if (mongoConnected) {
            await collection.insertOne(data);
        }
        
        // Add to local array
        transaction_details.push(data);

        // Blacklist recipient if anomalous
        if (isAnomaly && !blacklistedAccount) {
            if (mongoConnected) {
                await blacklistCollection.insertOne({
                    type: "account",
                    value: req.body.recipient_account_number,
                    reason: reasons,
                    timestamp: now
                });
            } else {
                inMemoryBlacklist.add(req.body.recipient_account_number);
            }
        }

        // Store phone number with transaction for later SMS
        data.phone = req.body.phone || "+916374672882";

        res.json({ 
            success: true, 
            anomalous: isAnomaly, 
            reasons: reasons,
            transaction_id: req.body.transaction_id
        });
        
    } catch (error) {
        console.error('Error processing transaction:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
})

app.listen(port, () => {
  console.log("Server is running on port 3001");
});
