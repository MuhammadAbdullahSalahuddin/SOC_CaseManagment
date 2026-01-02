// Switch to the database
db = db.getSiblingDB('suricata_db');

// Drop collection if exists (optional, first-time safety)
db.suricata_logs.drop();

// Create collection with JSON schema validator
db.createCollection('suricata_logs', {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      required: ["timestamp", "event_type", "src_ip", "dest_ip", "alert"],
      properties: {
        timestamp: {
          bsonType: "string",
          description: "Must be a string (ISO 8601 format) and is required"
        },
        event_type: {
          enum: ["alert", "stats", "metadata", "flow"],
          description: "Must be one of the allowed event types"
        },
        src_ip: {
          bsonType: "string",
          description: "Source IP Address is required"
        },
        dest_ip: {
          bsonType: "string",
          description: "Destination IP Address is required"
        },
        alert: {
          bsonType: "object",
          required: ["severity", "signature", "action"],
          properties: {
            severity: {
              bsonType: "int",
              minimum: 1,
              maximum: 5,
              description: "Severity must be an integer between 1 (Critical) and 5 (Info)"
            },
            signature: {
              bsonType: "string",
              description: "The name of the attack signature"
            },
            action: {
              enum: ["allowed", "blocked", "dropped"],
              description: "Action taken by Suricata"
            }
          }
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});
