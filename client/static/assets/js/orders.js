const BASE_URL = "https://127.0.0.1:3001/orders/";

async function getOrders() {
    try {
        const resp = await fetch(BASE_URL, { credentials: 'include', method: 'GET' });
        const orders = await resp.json();
        console.log(orders);
    } catch (err) {
        console.error(err);
    }
}

async function getOrderById(id) {
    try {
        const resp = await fetch(`${BASE_URL}/${id}`, { credentials: 'include', method: 'GET' });
        const order = await resp.json();
        console.log(order);
    } catch (err) {
        console.error(err);
    }
}

async function postOrder(orderData) {
    try {
        const resp = await fetch(BASE_URL, {
            method: 'POST',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orderData)
        });
        const result = await resp.json();
        console.log(result);
    } catch (err) {
        console.error(err);
    }
}

async function updateOrder(id, orderData) {
    try {
        const resp = await fetch(`${BASE_URL}/${id}`, {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orderData)
        });
        const result = await resp.json();
        console.log(result);
    } catch (err) {
        console.error(err);
    }
}

async function deleteOrder(id) {
    try {
        const resp = await fetch(`${BASE_URL}/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        const result = await resp.json();
        console.log(result);
    } catch (err) {
        console.error(err);
    }
}

document.getElementById('getOrdersForm').addEventListener('submit', function (e) {
    e.preventDefault();
    getOrders();
});

document.getElementById('getOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderId = document.getElementById('orderId').value;
    getOrderById(orderId);
});

document.getElementById('postOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderData = {
        id: document.getElementById('newOrderId').value,
        user_id: document.getElementById('newUserId').value,
        content: document.getElementById('newContent').value
    };
    postOrder(orderData);
});

document.getElementById('putOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderId = document.getElementById('updateOrderId').value;
    const orderData = {
        user_id: document.getElementById('updateUserId').value,
        content: document.getElementById('updateContent').value
    };
    updateOrder(orderId, orderData);
});

document.getElementById('deleteOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderId = document.getElementById('deleteOrderId').value;
    deleteOrder(orderId);
});

