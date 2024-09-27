async function main() {
    console.log("main.js")
    try {
        const resp = await fetch("https://127.0.0.1:3001/orders", {
            credentials: 'include'
        });
        const orders = await resp.json();
        console.log({ orders });
    } catch (err) {
        console.error(err);
    }
}

main();
