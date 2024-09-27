CREATE TABLE orders(
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    content TEXT
);
