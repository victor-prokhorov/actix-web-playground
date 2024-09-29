DROP TRIGGER IF EXISTS order_change_trigger ON orders;
-- trigger have old content thus next query would fail

UPDATE orders
SET product_id = '06fdd1be-5d59-41c2-8bcf-70bf279e83a3'
WHERE product_id IS NULL;
