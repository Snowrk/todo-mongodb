import { MongoClient } from "mongodb";
import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());
app.listen(3000, () => console.log("started in port 3000"));


const uri =
  "mongodb+srv://shinsan:5kmp60lRVx3wodUE@todo-users.8rdtq.mongodb.net/?retryWrites=true&w=majority&appName=todo-users";

const client = new MongoClient(uri);

async function run() {
  try {
    const database = client.db("Todos");
    const users = database.collection("Users");
    database.command({
      collMod: "Users",
      validator: {
        $jsonSchema: {
          bsonType: "object",
          required: ["name", "email", "password"],
          properties: {
            name: { bsonType: "string", minLength: 3 },
            email: { bsonType: "string", pattern: "^.+@.+..+$" },
            password: { bsonType: "string", minLength: 8 },
            todos: {
              bsonType: "array",
              items: {
                bsonType: "object",
                required: ["id", "todo", "status"],
                properties: {
                  id: { bsonType: "string" },
                  todo: { bsonType: "string" },
                  status: {
                    bsonType: "string",
                    enum: ["DONE", "PENDING", "IN PROGRESS", "COMPLETED"],
                  },
                },
              },
            },
          },
        },
      },
    });
    users.createIndex({ email: 1 }, { unique: true });
    const authenticateToken = (request, response, next) => {
      let jwtToken;
      const authHeader = request.headers["authorization"];
      if (authHeader !== undefined) {
        jwtToken = authHeader.split(" ")[1];
      }
      if (jwtToken === undefined) {
        response.status(401);
        response.send({ err: "Invalid JWT Token" });
      } else {
        jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
          if (error) {
            response.status(401);
            response.send({ err: "Invalid JWT Token" });
          } else {
            request.payload = payload;
            next();
          }
        });
      }
    };
    app.get("/", (request, response) => {
      response.send("Welcome to TODO API");
    });
    app.post("/users/", async (request, response) => {
      try {
        const { name, password, email } = request.body;
        const match = await users.findOne({ email: email });
        if (match) {
          response.status(400);
          response.send({ msg: "email already exists" });
        } else {
          const payload = {
            email: email,
          };
          const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
          const hashedPassword = await bcrypt.hash(password, 10);
          await users.insertOne({
            name: name,
            password: hashedPassword,
            email: email,
          });
          response.status(200);
          response.send({ jwtToken });
        }
      } catch (e) {
        console.log(e);
        response.status(500);
        response.send({ err: e });
      }
    });
    app.post("/login", async (request, response) => {
      try {
        const { email, password } = request.body;
        const match = await users.findOne({ email: email });
        if (!match) {
          response.status(400);
          response.send({ err: "User does not exist" });
        } else {
          const isPasswordMatched = await bcrypt.compare(
            password,
            match.password
          );
          if (isPasswordMatched) {
            const payload = {
              email: email,
            };
            const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
            response.status(200);
            response.send({ jwtToken });
          } else {
            response.status(400);
            response.send({ err: "Incorrect Password" });
          }
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.get("/profile/", authenticateToken, async (request, response) => {
      try {
        const { email } = request.payload;
        const match = await users.findOne({ email: email });
        if (match) {
          response.status(200);
          response.send(match);
        } else {
          response.status(400);
          response.send({ err: "cannot find the user" });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.put("/users/name", authenticateToken, async (request, response) => {
      try {
        const { email } = request.payload;
        const { name } = request.body;
        const match = await users.findOne({ email: email });
        if (!match) {
          response.status(400);
          response.send({ err: "cannot find the user" });
        } else {
          await users.updateOne({ email: email }, { $set: { name: name } });
          response.status(200);
          response.send({ msg: "successfully updated" });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.put("/users/email", authenticateToken, async (request, response) => {
      try {
        const { email } = request.payload;
        const newEmail = request.body.email;
        const match = await users.findOne({ email: email });
        if (!match) {
          response.status(400);
          response.send({ err: "cannot find the user" });
        } else {
          await users.updateOne(
            { email: email },
            { $set: { email: newEmail } }
          );
          const payload = {
            email: newEmail,
          };
          const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
          response.status(200);
          response.send({ jwtToken });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.put("/users/password", authenticateToken, async (request, response) => {
      try {
        const { email } = request.payload;
        const { password, pass } = request.body;
        const match = await users.findOne({ email: email });
        if (!match) {
          response.status(400);
          response.send({ err: "cannot find the user", match, email });
        } else {
          const isPasswordMatched = await bcrypt.compare(pass, match.password);
          if (isPasswordMatched) {
            const hashedPassword = await bcrypt.hash(password, 10);
            await users.updateOne(
              { email: email },
              { $set: { password: hashedPassword } }
            );
            response.status(200);
            response.send({ msg: "Password changed successfully" });
          } else {
            response.status(400);
            response.send({ msg: "Incorrect previous password" });
          }
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.get("/todos/", authenticateToken, async (request, response) => {
      try {
        const { email } = request.payload;
        const match = await users.findOne({ email: email });
        if (match) {
          response.status(200);
          response.send(match.todos ? match.todos : []);
        } else {
          response.status(400);
          response.send({ err: "cannot find the user" });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.post("/todos/", authenticateToken, async (request, response) => {
      try {
        const { id, todo, status } = request.body;
        const { email } = request.payload;
        const match = await users.findOne({ email: email });
        if (match) {
          const arr = match.todos ? match.todos : [];
          arr.push({ id, todo, status });
          await users.updateOne({ email: email }, { $set: { todos: arr } });
          response.status(200);
          response.send({ msg: "successfully incerted" });
        } else {
          response.status(400);
          response.send({ err: "cannot find user" });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.put("/todos/:todoId", authenticateToken, async (request, response) => {
      try {
        const { todoId } = request.params;
        const { status } = request.body;
        const { email } = request.payload;
        const match = await users.findOne({ email: email });
        if (match) {
          let arr = match.todos;
          const item = arr.filter((todo) => todo.id === todoId)[0];
          arr = arr.filter((todo) => todo.id !== todoId);
          arr.push({ id: todoId, todo: item.todo, status: status });
          await users.updateOne({ email: email }, { $set: { todos: arr } });
          response.status(200);
          response.send({ msg: "Status successfully updated" });
        } else {
          response.status(400);
          response.send({ err: "cannot find user" });
        }
      } catch (error) {
        console.log(error);
        response.status(500);
        response.send({ err: error });
      }
    });
    app.delete(
      "/todos/:todoId",
      authenticateToken,
      async (request, response) => {
        try {
          const { todoId } = request.params;
          const { email } = request.payload;
          const match = await users.findOne({ email: email });
          if (match) {
            let arr = match.todos;
            arr = arr.filter((todo) => todo.id !== todoId);
            await users.updateOne({ email: email }, { $set: { todos: arr } });
            response.status(200);
            response.send({ msg: "successfully deleted" });
          } else {
            response.status(400);
            response.send({ err: "cannot find user" });
          }
        } catch (error) {
          console.log(error);
          response.status(500);
          response.send({ err: error });
        }
      }
    );
  } catch (e) {
    console.log(e);
  }
}
run().catch(console.dir);

process.on("SIGINT", async () => {
  console.log("Gracefully shutting down...");
  try {
    await client.close(); // Close MongoDB connection
    console.log("MongoDB connection closed");
    process.exit(0); // Exit the process
  } catch (err) {
    console.error("Error while closing MongoDB connection", err);
    process.exit(1); // Exit with failure code
  }
});

process.on("SIGTERM", async () => {
  console.log("Received SIGTERM, shutting down gracefully...");
  try {
    await client.close();
    console.log("MongoDB connection closed");
    process.exit(0);
  } catch (err) {
    console.error("Error while closing MongoDB connection", err);
    process.exit(1);
  }
});
