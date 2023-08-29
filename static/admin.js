document.addEventListener('DOMContentLoaded', function () {
    const addAdminForm = document.querySelector('#add-admin');
    const addAdminSubmit = document.querySelector('#add-admin-submit');
    const confirmationMessage = document.querySelector('#confirmation-message');

    addAdminForm.addEventListener('submit', async function (event) {
        event.preventDefault();
        
        const formData = new FormData(addAdminForm);
        const response = await fetch(addAdminForm.action, {
            method: 'POST',
            body: formData,
        });

        if (response.ok) {
            const responseData = await response.json();
            confirmationMessage.textContent = `The user with username "${responseData.username}" was added as an admin.`;
            Swal.fire({
                title: 'Admin Added!',
                text: `The user with username "${responseData.username}" was added as an admin.`,
                icon: 'success',
                confirmButtonText: 'OK'
            });
        } else {
            Swal.fire({
                title: 'Error',
                text: 'There was an error adding the admin.',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        }
    });
});