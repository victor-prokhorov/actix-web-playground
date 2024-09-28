DROP TRIGGER IF EXISTS order_change_trigger ON orders;
CREATE OR REPLACE FUNCTION notify_order_change()
RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('orders', 'order.id ' || NEW.id || ' changed. order.content: ' || NEW.content);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER order_change_trigger
AFTER INSERT OR UPDATE ON orders
FOR EACH ROW EXECUTE FUNCTION notify_order_change();
