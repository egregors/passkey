document.getElementById('logout').addEventListener('click', async () => {
    try {
        const response = await fetch('/logout', {method: 'POST'});
        if (!response.ok) throw new Error('Logout failed');
        window.location.assign('/');
    } catch {
        document.getElementById('logout').textContent = 'Logout failed. Try again.';
    }
});
