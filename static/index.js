

function showConfirmation() {
    if (confirm("Are you sure you want to reset the database? This action cannot be undone.")) {
        document.getElementById('reset-form').submit();
    }
}

function showConfirmation2() {
    if (confirm("Are you sure you want to reset the database? This action cannot be undone.")) {
        document.getElementById('reset-posts').submit();
    }
}

// Confirm the deletion of a comment
document.addEventListener('DOMContentLoaded', () => {
    const deleteButtons = document.querySelectorAll('.delete-comment-button');

    deleteButtons.forEach(button => {
        button.addEventListener('click', (event) => {
            if (!confirm('Are you sure you want to delete this comment?')) {
                event.preventDefault();
            }
        });
    });
});

// Capture the current scroll position
function captureScrollPosition() {
    return window.scrollY;
  }

// Restore the scroll position
function restoreScrollPosition(scrollPosition) {
    window.scrollTo(0, scrollPosition);
  }

// Capture scroll position before form submission
document.querySelector('.add-comment-form').addEventListener('submit', function(event) {
    var scrollPosition = captureScrollPosition();
    document.querySelector('#scrollPosition').value = scrollPosition;
  });