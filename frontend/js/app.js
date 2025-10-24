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
            setUser(userInfo.username, userInfo.admin_level);
        } catch (error) {
            console.error('Session check failed:', error);
            logout();
        }
    }  async function login(username, password, totpCode = null) {
    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password, totp_code: totpCode })
      });
        const data = await response.json();
      console.log('Login response:', data);
      
      if (response.ok) {
        if (data.status === 'needs_2fa_setup' || data.status === 'needs_2fa') {
          console.log('Showing 2FA modal with:', {
            username: data.username,
            secret: data.secret,
            uri: data.provisioning_uri,
            qr_code: data.qr_code,
            isSetup: data.status === 'needs_2fa_setup'
          });
          // Show unified 2FA modal
          show2FAModal(data.username, data.status === 'needs_2fa_setup' ? {
            secret: data.secret,
            qr_code: data.qr_code
          } : null);
          return false;
        } else if (data.token) {
          localStorage.setItem('token', data.token);
          state.token = data.token;
          // Fetch admin level from server
          await checkSession();
          return true;
        }
      } 
      throw new Error(data.error || 'Login failed');
    } catch (error) {
      console.error('Login error:', error);
      loginError.textContent = error.message;
      loginError.classList.remove('hidden');
      return false;
    }
  }

  function show2FAModal(username, setupData = null) {
    // Create modal HTML
    const modal = document.createElement('div');
    modal.className = 'modal';
    
    const isSetup = setupData !== null;
    
    modal.innerHTML = `
      <div class="modal-content auth-modal">
        <h2>${isSetup ? 'Set Up Two-Factor Authentication' : '2FA Verification'}</h2>
        <div class="auth-content">
          ${isSetup ? `
          <div class="qr-section">
            <img src="${setupData.qr_code}" alt="QR Code" />
          </div>
          <div class="setup-steps">
            <ol>
              <li>Scan the QR code with your authenticator app</li>
              <li>Enter the code shown in your app</li>
            </ol>
          </div>
          ` : `
          <div class="verification-prompt">
            <p>Enter the code from your authenticator app</p>
          </div>
          `}
          
          <div class="verification-form">
            <input type="text" 
              id="verification-code" 
              class="form-input verification-input" 
              placeholder="000000" 
              maxlength="6" 
              pattern="[0-9]*"
              inputmode="numeric"
              autocomplete="off">
            <button id="verify-button" class="btn primary">
              ${isSetup ? 'Complete Setup' : 'Verify Code'}
            </button>
            <div id="verification-error" class="error hidden"></div>
          </div>

          ${isSetup ? `
          <details class="manual-setup">
            <summary>Can't scan? Manual setup</summary>
            <div class="secret-key">
              <code>${setupData.secret}</code>
              <button onclick="navigator.clipboard.writeText('${setupData.secret}')">Copy</button>
            </div>
          </details>
          ` : ''}
        </div>
      </div>
    `;
    document.body.appendChild(modal);

    const verifyBtn = document.getElementById('verify-button');
    const verificationError = document.getElementById('verification-error');
    const codeInput = document.getElementById('verification-code');

    // Auto-focus the input field
    codeInput.focus();

    // Add input validation
    codeInput.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/[^0-9]/g, '');
    });

    codeInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter' && codeInput.value.length === 6) {
        verifyBtn.click();
      }
    });

    verifyBtn.addEventListener('click', async () => {
      const code = codeInput.value.trim();
      
      if (code.length !== 6) {
        verificationError.textContent = 'Please enter a 6-digit code';
        verificationError.classList.remove('hidden');
        return;
      }

      try {
        if (isSetup) {
          const response = await fetch('/api/enable-2fa', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, code })
          });

          const data = await response.json();
          if (data.success) {
            modal.remove();
            // Try logging in again now that 2FA is set up
            login(username, passwordInput.value);
          } else {
            throw new Error(data.error || 'Invalid code');
          }
        } else {
          // Regular 2FA verification
          const success = await login(username, passwordInput.value, code);
          if (success) {
            modal.remove();
          }
        }
      } catch (error) {
        verificationError.textContent = error.message;
        verificationError.classList.remove('hidden');
      }
    });
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

  function setUser(username, adminLevel = 0){
    state.user = { username, adminLevel };
    userName.textContent = username;
    modal.classList.add('hidden');
    
    // Show/hide Users link based on user admin status (levels 1 or 3)
    const usersLink = document.querySelector('.link[data-route="users"]');
    if (usersLink) {
        usersLink.style.display = (adminLevel === 1 || adminLevel === 3) ? 'block' : 'none';
    }
    
    // Show/hide VDI Configs link based on VDI admin status (levels 2 or 3)
    const vdiLink = document.querySelector('.link[data-route="vdi-configs"]');
    if (vdiLink) {
        vdiLink.style.display = (adminLevel === 2 || adminLevel === 3) ? 'block' : 'none';
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

      // Fetch active VDIs
      const activeVdisResponse = await fetch('/api/active-vdis', {
        headers: {
          'Authorization': `Bearer ${state.token}`
        }
      });
      const activeVdisData = await activeVdisResponse.json();
      const connections = activeVdisData.connections || [];

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
      
      // Create Active VDIs section
      let activeVdisHtml = '';
      if (connections.length > 0) {
        activeVdisHtml = `
          <h2 class="h2" style="margin-top: 40px; margin-bottom: 20px;">Active VDIs</h2>
          <div class="active-vdis-list">
            <table class="vdi-table">
              <thead>
                <tr>
                  <th>Connection Name</th>
                  <th>Hostname</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
        `;
        
        for (const conn of connections) {
          const hostname = conn.parameters.hostname || 'N/A';
          
          activeVdisHtml += `
            <tr>
              <td>${conn.name}</td>
              <td>${hostname}</td>
              <td>
                <button class="btn small" onclick="connectToVDI('${conn.id}')">Connect</button>
              </td>
            </tr>
          `;
        }
        
        activeVdisHtml += `
              </tbody>
            </table>
          </div>
        `;
      }
      
      // Set the content once
      content.innerHTML = `
        <div>
          <h1 class="h1">Dashboard</h1>
          
          <h2 class="h2">Select an environment to launch</h2>
          <div class="card-row">
            ${cardHtml}
          </div>
          
          ${activeVdisHtml}
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
          <p class="error">Failed to load dashboard: ${error.message}</p>
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
    // Check if user is a user admin (level 1) or global admin (level 3)
    const isUserAdmin = state.user && (state.user.adminLevel === 1 || state.user.adminLevel === 3);
    
    if (!state.token || !state.user || !isUserAdmin) {
      content.innerHTML = `
        <div>
          <h1 class="h1">Unauthorized</h1>
          <p class="muted">You need administrator access to view this page.</p>
        </div>
      `;
      return;
    }

    // Map admin levels to names
    const adminLevels = {
      0: 'Regular User',
      1: 'User Admin',
      2: 'VDI Admin',
      3: 'Global Admin'
    };

    content.innerHTML = `
      <div>
        <h1 class="h1">User Management</h1>
        <div class="user-form">
          <h2>Add New User</h2>
          <input id="new-username" type="text" placeholder="Username" required />
          <input id="new-password" type="password" placeholder="Password" required />
          <div style="margin-bottom: 12px;">
            <label for="admin-level" style="display: block; margin-bottom: 6px; font-weight: 500;">Admin Level:</label>
            <select id="admin-level" style="width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); background: rgba(0, 0, 0, 0.3); color: #e6eef6; font-size: 1em; cursor: pointer;">
              <option value="0">Regular User</option>
              <option value="1">User Admin</option>
              <option value="2">VDI Admin</option>
              <option value="3">Global Admin</option>
            </select>
          </div>
          <div id="user-error" class="error hidden"></div>
          <button id="add-user-btn" class="btn primary">Add User</button>
        </div>
        <div id="users-list"></div>
      </div>
    `;

    const addUserBtn = document.getElementById('add-user-btn');
    const userError = document.getElementById('user-error');
    const newUsername = document.getElementById('new-username');
    const newPassword = document.getElementById('new-password');
    const adminLevel = document.getElementById('admin-level');

    addUserBtn.addEventListener('click', async () => {
      const username = newUsername.value.trim();
      const password = newPassword.value;
      const level = parseInt(adminLevel.value);
      
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
            admin_level: level
          })
        });

        const data = await response.json();
        if (response.ok) {
          alert('User created successfully!');
          newUsername.value = '';
          newPassword.value = '';
          adminLevel.value = '0';
          userError.classList.add('hidden');
          loadUsersList();
        } else {
          throw new Error(data.error || 'Failed to create user');
        }
      } catch (error) {
        userError.textContent = error.message;
        userError.classList.remove('hidden');
      }
    });

    // Load and display users list
    loadUsersList();

    async function loadUsersList() {
      try {
        const response = await fetch('/api/users/list', {
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to load users');
        }

        const data = await response.json();
        const usersList = document.getElementById('users-list');
        
        if (data.users && data.users.length > 0) {
          const usersHtml = `
            <h2 style="margin-top: 40px;">Existing Users</h2>
            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
              <thead>
                <tr style="background-color: rgba(255,255,255,0.05);">
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Username</th>
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Admin Level</th>
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Status</th>
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Created</th>
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Actions</th>
                </tr>
              </thead>
              <tbody>
                ${data.users.map(user => `
                  <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);" data-username="${user.username}">
                    <td style="padding: 12px;">${user.username}</td>
                    <td style="padding: 12px;">
                      <select class="user-admin-level" data-username="${user.username}" style="background: rgba(255,255,255,0.1); color: inherit; border: 1px solid rgba(255,255,255,0.2); padding: 6px; border-radius: 4px;">
                        <option value="0" ${user.admin_level === 0 ? 'selected' : ''}>Regular User</option>
                        <option value="1" ${user.admin_level === 1 ? 'selected' : ''}>User Admin</option>
                        <option value="2" ${user.admin_level === 2 ? 'selected' : ''}>VDI Admin</option>
                        <option value="3" ${user.admin_level === 3 ? 'selected' : ''}>Global Admin</option>
                      </select>
                    </td>
                    <td style="padding: 12px;">${user.is_locked ? 'Locked' : 'Active'}</td>
                    <td style="padding: 12px;">${new Date(user.created_at).toLocaleDateString()}</td>
                    <td style="padding: 12px;">
                      <button class="save-admin-level" data-username="${user.username}" style="background: rgba(124,58,237,0.5); color: white; border: 1px solid rgba(124,58,237,0.8); padding: 6px 12px; border-radius: 4px; cursor: pointer; margin-right: 8px; display: none;">Save</button>
                      <button class="delete-user" data-username="${user.username}" style="background: rgba(239,68,68,0.5); color: white; border: 1px solid rgba(239,68,68,0.8); padding: 6px 12px; border-radius: 4px; cursor: pointer;">Delete</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
          usersList.innerHTML = usersHtml;

          // Add event listeners for admin level dropdowns
          document.querySelectorAll('.user-admin-level').forEach(select => {
            select.addEventListener('change', (e) => {
              const saveBtn = e.target.closest('tr').querySelector('.save-admin-level');
              saveBtn.style.display = 'inline-block';
            });
          });

          // Add event listeners for save buttons
          document.querySelectorAll('.save-admin-level').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              const username = btn.dataset.username;
              const row = btn.closest('tr');
              const newLevel = parseInt(row.querySelector('.user-admin-level').value);
              
              try {
                const response = await fetch(`/api/users/${username}/admin-level`, {
                  method: 'PUT',
                  headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${state.token}`
                  },
                  body: JSON.stringify({ admin_level: newLevel })
                });

                const data = await response.json();
                if (response.ok) {
                  btn.style.display = 'none';
                  btn.textContent = 'Saved!';
                  setTimeout(() => {
                    btn.textContent = 'Save';
                  }, 1500);
                } else {
                  alert('Failed to update admin level: ' + data.error);
                }
              } catch (error) {
                alert('Error updating admin level: ' + error.message);
              }
            });
          });

          // Add event listeners for delete buttons
          document.querySelectorAll('.delete-user').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              const username = btn.dataset.username;
              
              if (confirm(`Are you sure you want to delete user "${username}"?`)) {
                try {
                  const response = await fetch(`/api/users/${username}`, {
                    method: 'DELETE',
                    headers: {
                      'Authorization': `Bearer ${state.token}`
                    }
                  });

                  const data = await response.json();
                  if (response.ok) {
                    alert('User deleted successfully!');
                    loadUsersList();
                  } else {
                    alert('Failed to delete user: ' + data.error);
                  }
                } catch (error) {
                  alert('Error deleting user: ' + error.message);
                }
              }
            });
          });
        }
      } catch (error) {
        console.error('Failed to load users:', error);
        document.getElementById('users-list').innerHTML = `<p class="error">Failed to load users list: ${error.message}</p>`;
      }
    }
  }

  function connectToVDI(connectionId) {
    try {
      if (!state.token) {
        throw new Error('Please login first');
      }

      // Get the guacURL from config
      fetch('/config.json')
        .then(res => res.json())
        .then(config => {
          const guacURL = config.guacURL;
          // Create base64-encoded connection string
          const string_with_nulls = `${connectionId}\x00c\x00postgresql`;
          const bytes_to_encode = new TextEncoder().encode(string_with_nulls);
          const base64Connection = btoa(String.fromCharCode.apply(null, bytes_to_encode));
          
          // Open Guacamole connection
          const guacUrl = `${guacURL}/#/client/${base64Connection}`;
          console.log('Opening Guacamole URL:', guacUrl);
          window.open(guacUrl, '_blank');
        });
    } catch (error) {
      console.error('Connect error:', error);
      alert(error.message);
    }
  }

  function renderPlaceholder(route){
    if (route === 'users') {
      renderUserManagement();
      return;
    }
    if (route === 'vdi-configs') {
      renderVDIManagement();
      return;
    }
    if (route === 'profile') {
      renderProfile();
      return;
    }
    content.innerHTML = `<div><h1 class=\"h1\">${route[0].toUpperCase()+route.slice(1)}</h1><p class=\"muted\">This section is a placeholder.</p></div>`;
  }

  function renderProfile() {
    if (!state.token || !state.user) {
      content.innerHTML = `
        <div>
          <h1 class="h1">Unauthorized</h1>
          <p class="muted">You need to be logged in to view this page.</p>
        </div>
      `;
      return;
    }

    const levelNames = {
      0: 'Regular User',
      1: 'User Admin',
      2: 'VDI Admin',
      3: 'Global Admin'
    };

    content.innerHTML = `
      <div>
        <h1 class="h1">User Profile</h1>
        
        <div class="profile-info">
          <h2>Account Information</h2>
          <p><strong>Username:</strong> ${state.user.username}</p>
          <p><strong>Admin Level:</strong> ${levelNames[state.user.adminLevel] || 'Unknown'}</p>
        </div>
        
        <div class="profile-form">
          <h2>Change Password</h2>
          <input type="password" id="current-password" class="form-input" placeholder="Current Password" />
          <input type="password" id="new-password" class="form-input" placeholder="New Password" />
          <input type="password" id="confirm-password" class="form-input" placeholder="Confirm Password" />
          <div id="password-error" class="error hidden"></div>
          <button id="change-password-btn" class="btn primary">Change Password</button>
          <div id="password-success" class="success hidden"></div>
        </div>
      </div>
    `;

    // Attach change password event listener
    document.getElementById('change-password-btn').addEventListener('click', handleChangePassword);
  }

  function handleChangePassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const errorDiv = document.getElementById('password-error');
    const successDiv = document.getElementById('password-success');
    
    // Clear messages
    errorDiv.classList.add('hidden');
    successDiv.classList.add('hidden');
    
    if (!currentPassword || !newPassword || !confirmPassword) {
      errorDiv.textContent = 'Please fill in all password fields';
      errorDiv.classList.remove('hidden');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      errorDiv.textContent = 'New passwords do not match';
      errorDiv.classList.remove('hidden');
      return;
    }
    
    if (newPassword.length < 8) {
      errorDiv.textContent = 'Password must be at least 8 characters';
      errorDiv.classList.remove('hidden');
      return;
    }
    
    // Call API to change password
    (async () => {
      try {
        const response = await fetch('/api/change-password', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${state.token}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            current_password: currentPassword,
            new_password: newPassword,
            confirm_password: confirmPassword
          })
        });
        
        const data = await response.json();
        
        if (response.ok) {
          successDiv.textContent = 'Password changed successfully!';
          successDiv.classList.remove('hidden');
          // Clear form
          document.getElementById('current-password').value = '';
          document.getElementById('new-password').value = '';
          document.getElementById('confirm-password').value = '';
          // Hide success message after 3 seconds
          setTimeout(() => {
            successDiv.classList.add('hidden');
          }, 3000);
        } else {
          errorDiv.textContent = data.error || 'Failed to change password';
          errorDiv.classList.remove('hidden');
        }
      } catch (error) {
        errorDiv.textContent = 'Error changing password: ' + error.message;
        errorDiv.classList.remove('hidden');
      }
    })();
  }

  function renderVDIManagement() {
    // Check if user is a VDI admin (level 2) or global admin (level 3)
    const isVDIAdmin = state.user && (state.user.adminLevel === 2 || state.user.adminLevel === 3);
    
    if (!state.token || !state.user || !isVDIAdmin) {
      content.innerHTML = `
        <div>
          <h1 class="h1">Unauthorized</h1>
          <p class="muted">You need VDI administrator access to view this page.</p>
        </div>
      `;
      return;
    }

    content.innerHTML = `
      <div>
        <h1 class="h1">VDI Configuration Management</h1>
        <div class="user-form">
          <h2>Upload VDI Configuration</h2>
          <p class="muted">Upload a JSON file to add a new VDI configuration</p>
          <input id="vdi-file-input" type="file" accept=".json" style="margin-bottom: 12px; padding: 8px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.2); width: 100%;" />
          <div id="upload-error" class="error hidden"></div>
          <button id="upload-vdi-btn" class="btn primary" style="margin-bottom: 20px;">Upload Configuration</button>
        </div>

        <h2 style="margin-top: 40px;">Existing Configurations</h2>
        <div id="vdi-configs-list"></div>
      </div>
    `;

    const uploadBtn = document.getElementById('upload-vdi-btn');
    const fileInput = document.getElementById('vdi-file-input');
    const uploadError = document.getElementById('upload-error');

    uploadBtn.addEventListener('click', async () => {
      const file = fileInput.files[0];
      
      if (!file) {
        uploadError.textContent = 'Please select a JSON file';
        uploadError.classList.remove('hidden');
        return;
      }

      if (!file.name.endsWith('.json')) {
        uploadError.textContent = 'Please select a valid JSON file';
        uploadError.classList.remove('hidden');
        return;
      }

      try {
        const fileContent = await file.text();
        const config = JSON.parse(fileContent);

        if (!config.vdsProperties || !config.guacPayload) {
          throw new Error('Invalid configuration file. Must contain vdsProperties and guacPayload');
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('filename', file.name);

        const response = await fetch('/api/vdi-profiles/upload', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${state.token}`
          },
          body: formData
        });

        const data = await response.json();
        if (response.ok) {
          alert('Configuration uploaded successfully!');
          fileInput.value = '';
          uploadError.classList.add('hidden');
          loadVDIConfigs();
        } else {
          throw new Error(data.error || 'Failed to upload configuration');
        }
      } catch (error) {
        uploadError.textContent = error.message;
        uploadError.classList.remove('hidden');
      }
    });

    loadVDIConfigs();

    async function loadVDIConfigs() {
      try {
        const response = await fetch('/api/vdi-profiles', {
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to load configurations');
        }

        const data = await response.json();
        const configsList = document.getElementById('vdi-configs-list');

        if (data.profiles && data.profiles.length > 0) {
          const configsHtml = `
            <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
              <thead>
                <tr style="background-color: rgba(255,255,255,0.05);">
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Filename</th>
                  <th style="padding: 12px; text-align: left; border-bottom: 1px solid rgba(255,255,255,0.1);">Actions</th>
                </tr>
              </thead>
              <tbody>
                ${data.profiles.map(profile => `
                  <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                    <td style="padding: 12px; word-break: break-word;">${profile.filename}</td>
                    <td style="padding: 12px;">
                      <button class="view-config" data-filename="${profile.filename}" style="background: rgba(124,58,237,0.5); color: white; border: 1px solid rgba(124,58,237,0.8); padding: 6px 12px; border-radius: 4px; cursor: pointer; margin-right: 8px;">View</button>
                      <button class="download-config" data-filename="${profile.filename}" style="background: rgba(34,197,94,0.5); color: white; border: 1px solid rgba(34,197,94,0.8); padding: 6px 12px; border-radius: 4px; cursor: pointer; margin-right: 8px;">Download</button>
                      <button class="delete-config" data-filename="${profile.filename}" style="background: rgba(239,68,68,0.5); color: white; border: 1px solid rgba(239,68,68,0.8); padding: 6px 12px; border-radius: 4px; cursor: pointer;">Delete</button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          `;
          configsList.innerHTML = configsHtml;

          // Add event listeners for view buttons
          document.querySelectorAll('.view-config').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              const filename = btn.dataset.filename;
              await viewVDIConfig(filename);
            });
          });

          // Add event listeners for download buttons
          document.querySelectorAll('.download-config').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              const filename = btn.dataset.filename;
              downloadVDIConfig(filename);
            });
          });

          // Add event listeners for delete buttons
          document.querySelectorAll('.delete-config').forEach(btn => {
            btn.addEventListener('click', async (e) => {
              const filename = btn.dataset.filename;
              if (confirm(`Are you sure you want to delete "${filename}"?`)) {
                await deleteVDIConfig(filename);
              }
            });
          });
        } else {
          configsList.innerHTML = `<p class="muted">No VDI configurations found. Upload a JSON file to add one.</p>`;
        }
      } catch (error) {
        console.error('Failed to load configs:', error);
        document.getElementById('vdi-configs-list').innerHTML = `<p class="error">Failed to load configurations: ${error.message}</p>`;
      }
    }

    async function viewVDIConfig(filename) {
      try {
        const response = await fetch(`/api/vdi-profiles/${filename}`, {
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to load configuration');
        }

        const config = await response.json();
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.innerHTML = `
          <div style="background: linear-gradient(180deg, rgba(255,255,255,0.04), rgba(255,255,255,0.02)); padding: 30px; border-radius: 16px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; box-shadow: 0 10px 40px rgba(2,6,23,0.8);">
            <h2 style="margin: 0 0 20px; color: white;">${filename}</h2>
            <pre style="background: rgba(0,0,0,0.3); padding: 15px; border-radius: 8px; overflow-x: auto; color: #a5b4fc;">${JSON.stringify(config, null, 2)}</pre>
            <button id="close-modal-btn" style="background: linear-gradient(90deg,#7c3aed,#06b6d4); color: white; border: 0; padding: 10px 20px; border-radius: 8px; cursor: pointer; margin-top: 15px;">Close</button>
          </div>
        `;
        document.body.appendChild(modal);
        
        // Add event listener to close button
        document.getElementById('close-modal-btn').addEventListener('click', () => {
          modal.remove();
        });
      } catch (error) {
        alert('Failed to load configuration: ' + error.message);
      }
    }

    async function downloadVDIConfig(filename) {
      try {
        // Fetch the file and create a blob download
        const response = await fetch(`/api/vdi-profiles/download/${filename}`, {
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });

        if (!response.ok) {
          throw new Error('Failed to download configuration');
        }

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
      } catch (error) {
        alert('Failed to download configuration: ' + error.message);
      }
    }

    async function deleteVDIConfig(filename) {
      try {
        const response = await fetch(`/api/vdi-profiles/${filename}`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Bearer ${state.token}`
          }
        });

        const data = await response.json();
        if (response.ok) {
          alert('Configuration deleted successfully!');
          loadVDIConfigs();
        } else {
          alert('Failed to delete configuration: ' + data.error);
        }
      } catch (error) {
        alert('Error deleting configuration: ' + error.message);
      }
    }
  }

  // initial state

  // Check session on load if we have a token
  if (state.token) {
    checkSession();
  } else {
    modal.classList.remove('hidden');
  }
})();
