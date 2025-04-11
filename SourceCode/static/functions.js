let posts = [];

function redirectToRegister() {
    window.location.href = "/register";
}

function welcome() {
    document.addEventListener("keypress", function (event) {
        if (event.code === "Enter") {
            createNewPost();
        }
    });

    getPosts();
    setInterval(getPosts, 3000);
}

function createNewPost() {
    const postMessageInput = document.getElementById("postMessageInput");
    const message = postMessageInput.value;
    postMessageInput.value = "";

    if (!message) {
        alert("You need to type something in order to post!");
        return;
    }

    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            getPosts();
        }
    };
    const messageJSON = { "message": message };
    request.open("POST", "/posts");
    request.setRequestHeader('Content-Type', 'application/json');
    request.send(JSON.stringify(messageJSON));
}

function getPosts() {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            updatePosts(JSON.parse(this.responseText));
        }
    };
    request.open("GET", "/posts");
    request.send();
}

function updatePosts(serverPosts) {
    //handle only post existence
    const localPostIds = posts.map(post => post.id);
    const serverPostIds = serverPosts.map(post => post.id);

    // Delete local posts that don't exist on the server
    localPostIds.forEach(id => {
        if (!serverPostIds.includes(id)) {
            const elem = document.getElementById(id);
            if (elem) elem.remove();
        }
    });

    // add new post
    serverPosts.forEach(serverPost => {
        if (!localPostIds.includes(serverPost.id)) {
            addPostToContainer(serverPost);
        }
    });

    posts = serverPosts;
}

function addPostToContainer(messageJSON) {
    const postsContainer = document.getElementById("postsContainer");
    postsContainer.insertAdjacentHTML("afterbegin", createPostHTML(messageJSON));
}

function createPostHTML(postData) {
    return `
        <div class="post-container" id="${postData.id}">
            <div class="post-username">${postData.author}</div>
            <div class="post-content">${postData.content}</div>
            <div class="post-timestamp">
                ${new Date(postData.timestamp).toLocaleString()}
            </div>
            <button class="delete-button" onclick="deletePost('${postData.id.toString()}')">Delete</button>

        </div>
    `;
}

function deletePost(postId) {
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4) {
            if (this.status === 204) {
                alert("Post deleted successfully!");
                getPosts();  // Refresh posts after deletion
            } else {
                alert("Failed to delete the post. You may not have permission.");
            }
        }
    };
    request.open("DELETE", `/posts/${postId}`);
    request.send();
}

function deleteAccount(event) {
    event.preventDefault();  // Prevent page reload on link click
    if (confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
        const request = new XMLHttpRequest();
        request.onreadystatechange = function () {
            if (this.readyState === 4) {
                if (this.status === 200) {
                    alert("Your account has been deleted successfully.");
                    window.location.href = "/logout";  // Redirect to logout page after account deletion
                } else {
                    alert("Failed to delete your account. Please try again later.");
                }
            }
        };
        request.open("POST", location.origin + "/delete_account");  // Use location.origin here
        request.send();  
    }
}




