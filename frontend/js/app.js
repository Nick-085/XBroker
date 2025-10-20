// Front-end behavior with backend integration
(function(){
  const state = {
    user: null,
    token: localStorage.getItem('token')
  };

  // Elements
  const modal = document.getElementById('login-modal');
  const loginBtn = document.getElementById('login-btn');
  const usernameInput = document.getElementById('username-input');
  const passwordInput = document.getElementById('password-input');
  const loginError = document.getElementById('login-error');
  const userName = document.getElementById('user-name');
  const content = document.getElementById('content');
  const links = document.querySelectorAll('.link');

    async function checkSession() {
        try {
            // Check session first
            const sessionResponse = await fetch('/api/session', {
                headers: {
                    'Authorization': `Bearer ${state.token}`
                }
            });
            const sessionData = await sessionResponse.json();
            if (!sessionData.authenticated) {
                logout();
                return;
            }

            // Then get user info
            const userInfoResponse = await fetch('/api/user-info', {
                headers: {
                    'Authorization': `Bearer ${state.token}`
                }
            });
            const userInfo = await userInfoResponse.json();
            setUser(userInfo.username, userInfo.is_admin);
        } catch (error) {
            console.error('Session check failed:', error);
            logout();
        }
    }  async function login(username, password) {
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });
      const data = await response.json();
      if (response.ok && data.token) {
        localStorage.setItem('token', data.token);
        state.token = data.token;
        setUser(data.username);
        return true;
      } else {
        throw new Error(data.error || 'Login failed');
      }
    } catch (error) {
      console.error('Login error:', error);
      loginError.textContent = error.message;
      loginError.classList.remove('hidden');
      return false;
    }
  }

  function logout() {
    state.user = null;
    state.token = null;
    localStorage.removeItem('token');
    userName.textContent = 'Guest';
    modal.classList.remove('hidden');
    content.innerHTML = '';
  }

  async function launchDesktop(card, vdiFile) {
    try {
      if (!state.token) {
        throw new Error('Please login first');
      }

      card.classList.add('loading');
      
      // Get the guacURL from config
      const configResponse = await fetch('/config.json');
      const config = await configResponse.json();
      const guacURL = config.guacURL;
      
      const response = await fetch('/api/launch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${state.token}`
        },
        body: JSON.stringify({
          vdiFile,
          uuid: card.dataset.uuid,
          cidr: card.dataset.cidr
        })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Launch failed');
      }

      const responseData = await response.json();
      
      if (!responseData.connection_string) {
        if (responseData.error) {
          throw new Error(responseData.error);
        }
        throw new Error('Server response missing connection string');
      }
      
      const base64Connection = responseData.connection_string;

      // Wait a moment to ensure the broker script has time to start the VM
      await new Promise(resolve => setTimeout(resolve, 2000));
      console.log('Base64 connection string:', base64Connection);
      
      // Open Guacamole directly to the connection using the guacURL from config
      const guacUrl = `${guacURL}/#/client/${base64Connection}`;
      console.log('Opening URL:', guacUrl);
      window.open(guacUrl, '_blank');
    } catch (error) {
      console.error('Desktop launch error:', error);
      alert(error.message);
    } finally {
      card.classList.remove('loading');
    }
  }

  function setUser(username, isAdmin = false){
    state.user = { username, isAdmin };
    userName.textContent = username;
    modal.classList.add('hidden');
    
    // Show/hide Users link based on admin status
    const usersLink = document.querySelector('.link[data-route="users"]');
    if (usersLink) {
        usersLink.style.display = isAdmin ? 'block' : 'none';
    }
    
    renderHome();
  }

  loginBtn.addEventListener('click', async ()=>{
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    
    if (!username || !password) {
      loginError.textContent = 'Please enter both username and password';
      loginError.classList.remove('hidden');
      return;
    }
    
    await login(username, password);
  });

  [usernameInput, passwordInput].forEach(input => {
    input.addEventListener('keydown', (e)=>{
      if(e.key === 'Enter') loginBtn.click();
    });
  });
  
  document.getElementById('logout-btn').addEventListener('click', async () => {
    try {
      if (state.token) {
        await fetch('/api/logout', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });
      }
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      logout();
    }
  });

  links.forEach(btn=>btn.addEventListener('click', (e)=>{
    // Skip if it's an external link
    if (btn.tagName === 'A' && btn.target === '_blank') return;
    
    e.preventDefault();
    links.forEach(b=>b.classList.remove('active'));
    btn.classList.add('active');
    // simple routing
    const route = btn.dataset.route;
    if(route === 'home') renderHome();
    else renderPlaceholder(route);
  }));

  async function renderHome(){
    try {
      if (!state.token) {
        modal.classList.remove('hidden');
        return;
      }
      // Fetch VDS profiles from new endpoint
      const response = await fetch('/api/vds-profiles', {
        headers: {
          'Authorization': `Bearer ${state.token}`
        }
      });
      const data = await response.json();
      
      if (!data.profiles) {
        throw new Error('No profiles available');
      }

      // Create card HTML for each profile
      const cardHtml = data.profiles.map(profile => 
        cardHTML(
          profile.displayName,
          profile.description || `VDI Environment with UUID: ${profile.uuid}`,
          profile.imgLocation || 'assets/cover1.svg',
          profile.filename,
          profile.uuid,
          profile.expected_cidr_range
        )
      ).join('');
      
      // Set the content once
      content.innerHTML = `
        <div>
          <h1 class="h1">Desktop Environments</h1>
          <div class="h2">Select an environment to launch</div>

          <div class="card-row">
            ${cardHtml}
          </div>
        </div>
      `;

      // Add click handlers to cards
      document.querySelectorAll('.card').forEach(card => {
        card.addEventListener('click', async () => {
          if (!card.classList.contains('loading')) {
            const vdiFile = card.dataset.vdi;
            await launchDesktop(card, vdiFile);
          }
        });
      });
    } catch (error) {
      // Show error if there's a problem
      content.innerHTML = `
        <div>
          <h1 class="h1">Error</h1>
          <p class="error">Failed to load desktop environments: ${error.message}</p>
        </div>
      `;
    }
  }

  function cardHTML(title, desc, img, vdiFile, uuid, cidr){
    return `
      <div class="card" 
           data-vdi="${vdiFile}"
           data-uuid="${uuid}"
           data-cidr="${cidr}">
        <div class="cover" style="background-image:url('${img}');">${title}</div>
        <div class="title">${title}</div>
        <div class="desc">${desc}</div>
      </div>
    `;
  }

  function renderUserManagement() {
    if (!state.token || !state.user || !state.user.isAdmin) {
      content.innerHTML = `
        <div>
          <h1 class="h1">Unauthorized</h1>
          <p class="muted">You need administrator access to view this page.</p>
        </div>
      `;
      return;
    }

    content.innerHTML = `
      <div>
        <h1 class="h1">User Management</h1>
        <div class="user-form">
          <h2>Add New User</h2>
          <input id="new-username" type="text" placeholder="Username" required />
          <input id="new-password" type="password" placeholder="Password" required />
          <label>
            <input id="is-admin" type="checkbox" /> Admin User
          </label>
          <div id="user-error" class="error hidden"></div>
          <button id="add-user-btn" class="btn primary">Add User</button>
        </div>
      </div>
    `;

    const addUserBtn = document.getElementById('add-user-btn');
    const userError = document.getElementById('user-error');
    const newUsername = document.getElementById('new-username');
    const newPassword = document.getElementById('new-password');
    const isAdmin = document.getElementById('is-admin');

    addUserBtn.addEventListener('click', async () => {
      const username = newUsername.value.trim();
      const password = newPassword.value;
      
      if (!username || !password) {
        userError.textContent = 'Please enter both username and password';
        userError.classList.remove('hidden');
        return;
      }

      try {
        const response = await fetch('/api/users', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${state.token}`
          },
          body: JSON.stringify({
            username,
            password,
            is_admin: isAdmin.checked
          })
        });

        const data = await response.json();
        if (response.ok) {
          alert('User created successfully!');
          newUsername.value = '';
          newPassword.value = '';
          isAdmin.checked = false;
        } else {
          throw new Error(data.error || 'Failed to create user');
        }
      } catch (error) {
        userError.textContent = error.message;
        userError.classList.remove('hidden');
      }
    });
  }

  function renderPlaceholder(route){
    if (route === 'users') {
      renderUserManagement();
      return;
    }
    content.innerHTML = `<div><h1 class=\"h1\">${route[0].toUpperCase()+route.slice(1)}</h1><p class=\"muted\">This section is a placeholder.</p></div>`;
  }

  // initial state

  // Check session on load if we have a token
  if (state.token) {
    checkSession();
  } else {
    modal.classList.remove('hidden');
  }
})();
