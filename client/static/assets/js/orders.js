/**
 * @typedef {import('../../../../common/common').Order} Order
 */

const BASE_URL = "https://127.0.0.1:3001/orders/";

/**
 * 
 * @param {Array<Order>} orders 
 */
function processOrders(orders) {
    for (const order of orders) {
        console.log("processing...");
        console.log({ order });
    }
}

async function getOrders() {
    try {
        const resp = await fetch(BASE_URL, { credentials: 'include', method: 'GET' });
        const orders = await resp.json();
        processOrders(orders);
    } catch (err) {
        console.error(err);
    }
}

async function getOrderById(id) {
    try {
        const resp = await fetch(`${BASE_URL}${id}`, { credentials: 'include', method: 'GET' });
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
            body: JSON.stringify({
                content: orderData.content,
                id: orderData.id || null,
                user_id: orderData.id || null,
            })
        });
        const result = await resp.json();
        console.log(result);
    } catch (err) {
        console.error(err);
    }
}

async function updateOrder(id, orderData) {
    try {
        const resp = await fetch(`${BASE_URL}${id}`, {
            method: 'PUT',
            credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orderData)
        });
        console.log('ok');
    } catch (err) {
        console.error(err);
    }
}

async function deleteOrder(id) {
    try {
        const resp = await fetch(`${BASE_URL}${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        console.log('ok');
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
    const orderId = document.getElementById('orderId').value || null;
    getOrderById(orderId);
});

document.getElementById('postOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderData = {
        id: document.getElementById('newOrderId').value || null,
        user_id: document.getElementById('newUserId').value || null,
        content: document.getElementById('newContent').value || null
    };
    postOrder(orderData);
});

document.getElementById('putOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderId = document.getElementById('updateOrderId').value || null;
    const orderData = {
        user_id: document.getElementById('updateUserId').value || null,
        content: document.getElementById('updateContent').value || null
    };
    updateOrder(orderId, orderData);
});

document.getElementById('deleteOrderForm').addEventListener('submit', function (e) {
    e.preventDefault();
    const orderId = document.getElementById('deleteOrderId').value || null;
    deleteOrder(orderId);
});

