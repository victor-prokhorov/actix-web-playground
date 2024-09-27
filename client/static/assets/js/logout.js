async function main() {
    try {
        const response = await fetch('https://127.0.0.1:3001/logout', {
            credentials: 'include',
        });
        console.log({response})
        if (response.ok) {
            window.location.href = 'https://127.0.0.1:3000/index.html';
        } else {
            throw new Error("not a 200");
        }
    } catch (err) {
        console.error(err);
    }
}

main()
