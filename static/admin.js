function addAdmin() {
    // Send a POST request to the /admin route to add the admin
    // You can use fetch or an AJAX library like jQuery.ajax for this purpose
    fetch("/admin", {
        method: "POST",
        body: new FormData(document.getElementById("add-admin")),
    })
    .then((response) => response.json())  // Assuming the server returns JSON data
    .then((data) => {
        // Check if the admin was added successfully (you can define the criteria for success)
        if (data.username) {
            // Clear the input field
            document.getElementById("admin-username").value = "";

            // Show a pop-up message or alert
            alert(`User '${data.username}' has been added as an admin.`);
        } else {
            alert("User not found.");
        }
    })
    .catch((error) => {
        console.error("Error:", error);
    });
}

document.addEventListener("DOMContentLoaded", function () {
    // Find the submit button by its ID
    const addButton = document.getElementById("add-admin-submit");

    // Add an onclick event handler to the button
    addButton.addEventListener("click", function () {
        // Call the addAdmin function when the button is clicked
        addAdmin();
    });
});