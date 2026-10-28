const queryInput = document.getElementById('query-input');
const sendBtn = document.getElementById('send-btn');
const messagesContainer = document.getElementById('messages-container');
const useAiToggle = document.getElementById('use-ai-toggle');
const resultsContent = document.getElementById('results-content');
const resultSectionTemplate = document.getElementById('result-section-template');
const aiSearchLink = document.getElementById('ai-search-link');
const mainHeaderH1 = document.querySelector('.top-header h1');
const mainHeaderP = document.querySelector('.top-header p');

let currentMode = 'general'; // 'general' or 'ai-deep'

// Focus input on load
window.onload = () => queryInput.focus();

// Event Listeners
sendBtn.addEventListener('click', handleSearch);
queryInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') handleSearch();
});

aiSearchLink.addEventListener('click', (e) => {
    e.preventDefault();
    setMode('ai-deep');
});

document.querySelector('.nav-links a:first-child').addEventListener('click', (e) => {
    e.preventDefault();
    setMode('general');
});

function setMode(mode) {
    currentMode = mode;
    // Update active class
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    if (mode === 'general') {
        document.querySelector('.nav-links a:first-child').classList.add('active');
        mainHeaderH1.textContent = 'Vulnerability Intelligence';
        mainHeaderP.textContent = 'Search across Metasploit, Exploit-DB, and SSTI payloads.';
        queryInput.placeholder = 'Enter keyword (e.g., windows, ssh, apache)...';
    } else {
        aiSearchLink.classList.add('active');
        mainHeaderH1.textContent = 'AI Deep Search';
        mainHeaderP.textContent = 'Strictly for CVEs (CVE-2021-44228) or Service Versions (Apache 2.4.49).';
        queryInput.placeholder = 'Enter CVE ID or Service + Version...';
    }
    queryInput.focus();
}

async function handleSearch() {
    const query = queryInput.value.trim();
    if (!query) return;

    // Clear input
    queryInput.value = '';
    
    // Disable inputs while processing
    sendBtn.disabled = true;
    queryInput.disabled = true;

    // Display user message
    addMessage(query, 'user');
    
    try {
        if (currentMode === 'ai-deep') {
            const loadingId = addLoadingMessage('ai');
            const res = await fetch('/api/ai_deep_search', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ query })
            });
            removeMessage(loadingId);
            
            if (res.ok) {
                const result = await res.json();
                if (result.valid) {
                    renderAiDeepResults(result.data, query);
                } else {
                    addMessage(result.error, 'system');
                }
            } else {
                addMessage("Failed to communicate with AI Search API.", 'system');
            }
            return; // Exit after AI deep search
        }

        // Show fetching data message
        const searchLoadingId = addLoadingMessage('system');
        
        // Search Databases
        const searchRes = await fetch('/api/search', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });

        removeMessage(searchLoadingId);

        if (searchRes.ok) {
            const searchData = await searchRes.json();
            
            // Count total results
            let totalResults = searchData.metasploit.length + 
                               searchData.ssti.length + 
                               searchData.exploitdb_titles.length +
                               (searchData.searchsploit ? searchData.searchsploit.length : 0);

            addMessage(`Found ${totalResults} raw database matches for "${query}". Check the Database Panel for details.`, 'system');
            
            if (searchData.ai_interpretation) {
                addMessage(searchData.ai_interpretation, 'ai');
            }

            // Add a special AI message if a live search URL is found (CVE detected)
            if (searchData.live_search_url) {
                setTimeout(() => {
                    addMessage(`I've detected a CVE ID in your query. You can view the live, verified exploit entries on Exploit-DB here: <a href="${searchData.live_search_url}" target="_blank" class="live-search-link">Live Exploit-DB Results <i class="fa-solid fa-external-link"></i></a>`, 'ai');
                }, 500);
            }
            
            // Update results panel
            renderResults(searchData);

        } else {
            addMessage("An error occurred while searching databases.", 'system');
        }

    } catch (error) {
        console.error(error);
        addMessage(`Network Error: ${error.message}`, 'system');
    } finally {
        sendBtn.disabled = false;
        queryInput.disabled = false;
        queryInput.focus();
    }
}

function addMessage(text, type) {
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${type}-msg`;
    
    let iconClass = 'fa-robot';
    if (type === 'user') iconClass = 'fa-user';
    if (type === 'ai') iconClass = 'fa-wand-magic-sparkles';

    // Format text: replaces newlines with <br>
    const formattedText = text.replace(/\n/g, '<br>');

    msgDiv.innerHTML = `
        <div class="avatar"><i class="fa-solid ${iconClass}"></i></div>
        <div class="msg-content">
            <p>${formattedText}</p>
        </div>
    `;
    
    messagesContainer.appendChild(msgDiv);
    scrollToBottom();
    return msgDiv.id; // Usually not needed unless tracking ID
}

function addLoadingMessage(type) {
    const id = 'msg-' + Date.now();
    const msgDiv = document.createElement('div');
    msgDiv.className = `message ${type}-msg`;
    msgDiv.id = id;
    
    let iconClass = type === 'ai' ? 'fa-wand-magic-sparkles' : 'fa-robot';

    msgDiv.innerHTML = `
        <div class="avatar"><i class="fa-solid ${iconClass}"></i></div>
        <div class="msg-content">
            <div class="loading-dots">
                <span></span><span></span><span></span>
            </div>
        </div>
    `;
    
    messagesContainer.appendChild(msgDiv);
    scrollToBottom();
    return id;
}

function removeMessage(id) {
    const msg = document.getElementById(id);
    if (msg) msg.remove();
}

function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
}

function renderResults(data) {
    resultsContent.innerHTML = ''; // Clear existing

    if (data.metasploit.length === 0 && data.ssti.length === 0 && data.exploitdb_titles.length === 0 && (!data.searchsploit || data.searchsploit.length === 0)) {
        resultsContent.innerHTML = `
            <div class="empty-state">
                <i class="fa-solid fa-circle-info"></i>
                <p>No local database matches found.</p>
                <div style="margin-top: 15px; display: flex; flex-direction: column; gap: 10px; width: 100%;">
                    <a href="${data.live_search_url}" target="_blank" class="live-search-link" style="text-align: center; margin: 0;"><i class="fa-solid fa-globe"></i> Search Exploit-DB Live</a>
                    <a href="${data.google_search_url}" target="_blank" class="live-search-link" style="text-align: center; margin: 0; background: #4285f4;"><i class="fa-brands fa-google"></i> Search via Google</a>
                </div>
            </div>
        `;
        return;
    }

    // Always add Live Search Section at top if not empty
    const liveSection = createSection('Live Web Search');
    const liveContainer = liveSection.querySelector('.section-items');
    const liveSearchContent = `
        <div style="display: flex; gap: 10px; flex-wrap: wrap; padding: 5px;">
            <a href="${data.live_search_url}" target="_blank" class="btn btn-primary" style="padding: 8px 16px; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 8px;"><i class="fa-solid fa-magnifying-glass"></i> Exploit-DB Search</a>
            <a href="${data.google_search_url}" target="_blank" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 8px;"><i class="fa-brands fa-google"></i> Google Dorks</a>
        </div>
    `;
    const liveItem = createResultItem("Extended Search Options", liveSearchContent);
    liveContainer.appendChild(liveItem);
    resultsContent.appendChild(liveSection);

    // Metasploit
    if (data.metasploit.length > 0) {
        const section = createSection('Metasploit Modules');
        const container = section.querySelector('.section-items');
        
        data.metasploit.forEach(item => {
            container.appendChild(createResultItem(item.Module, item.Description));
        });
        resultsContent.appendChild(section);
    }

    // SSTI
    if (data.ssti.length > 0) {
        const section = createSection('SSTI Payloads');
        const container = section.querySelector('.section-items');
        
        data.ssti.forEach(item => {
            const desc = `<strong>Category:</strong> ${item.Category}<br><strong>Payload:</strong> <code style="color:var(--accent-color)">${item.Payload}</code>`;
            container.appendChild(createResultItem(item.Description || "SSTI Payload", desc, item.Platform));
        });
        resultsContent.appendChild(section);
    }

    // Exploit-DB (Legacy Titles)
    if (data.exploitdb_titles.length > 0) {
        const section = createSection('Exploit-DB (Legacy Datasets)');
        const container = section.querySelector('.section-items');
        
        data.exploitdb_titles.forEach(title => {
            container.appendChild(createResultItem(title, ""));
        });
        resultsContent.appendChild(section);
    }
    
    // SearchSploit with Links
    if (data.searchsploit && data.searchsploit.length > 0) {
        const section = createSection('Exploit-DB (Live Links)');
        const container = section.querySelector('.section-items');
        
        data.searchsploit.forEach(item => {
            const externalLink = `<a href="${item.URL}" target="_blank" class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.75rem; margin-top: 10px; display: inline-flex; align-items: center; gap: 5px;"><i class="fa-solid fa-arrow-up-right-from-square"></i> Exploit-DB</a>`;
            const rawCodeBtn = item.RawURL ? `<button onclick="fetchAndShowCode('${item.RawURL}', '${item.Title.replace(/'/g, "\\'")}')" class="btn btn-primary" style="padding: 6px 12px; font-size: 0.75rem; margin-top: 10px; display: inline-flex; align-items: center; gap: 5px;"><i class="fa-solid fa-code"></i> View Raw Code</button>` : '';
            
            const desc = `<div style="display: flex; gap: 10px; flex-wrap: wrap;">${externalLink}${rawCodeBtn}</div>`;
            container.appendChild(createResultItem(item.Title, desc, "SearchSploit"));
        });
        resultsContent.appendChild(section);
    }
}

function createSection(title) {
    const fragment = resultSectionTemplate.content.cloneNode(true);
    fragment.querySelector('.section-title').textContent = title;
    // We return the actual div element, not the fragment, so we can append to it
    const div = document.createElement('div');
    div.appendChild(fragment);
    return div.firstElementChild;
}

function createResultItem(title, description, badgeText = null) {
    const div = document.createElement('div');
    div.className = 'result-item';
    
    let badgeHTML = badgeText ? `<div class="result-badge">${badgeText}</div>` : '';
    
    div.innerHTML = `
        ${badgeHTML}
        <div class="result-item-title">${title}</div>
        ${description ? `<div class="result-item-desc">${description}</div>` : ''}
    `;
    return div;
}

// Modal Logic
const modal = document.getElementById('code-modal');
const closeBtn = document.querySelector('.close-modal');
const modalCode = document.getElementById('modal-code');
const modalTitle = document.getElementById('modal-title');

closeBtn.onclick = function() {
    modal.classList.remove('show');
}

window.onclick = function(event) {
    if (event.target == modal) {
        modal.classList.remove('show');
    }
}

async function fetchAndShowCode(url, title) {
    modalTitle.textContent = title;
    modalCode.textContent = "Loading exploit code...";
    modal.classList.add('show');
    
    try {
        const res = await fetch(`/api/fetch_exploit?url=${encodeURIComponent(url)}`);
        if (res.ok) {
            const data = await res.json();
            if (data.code) {
                modalCode.textContent = data.code;
            } else {
                modalCode.textContent = data.error || "Failed to load code.";
            }
        } else {
            modalCode.textContent = "Error fetching code from server.";
        }
    } catch (e) {
        modalCode.textContent = "Network error: " + e.message;
    }
}

function renderAiDeepResults(data, query) {
    // 1. Add AI Analysis message
    addMessage(data.analysis, 'ai');
    
    // 2. Update results panel
    resultsContent.innerHTML = '';
    const section = createSection('AI Found Exploits');
    const container = section.querySelector('.section-items');
    
    if (data.exploits && data.exploits.length > 0) {
        data.exploits.forEach(exp => {
            const desc = `${exp.description ? `${exp.description}<br>` : ''}<a href="${exp.url}" target="_blank" rel="noopener noreferrer" class="btn btn-primary" style="padding: 6px 12px; font-size: 0.75rem; margin-top: 10px; display: inline-flex; align-items: center; gap: 5px;"><i class="fa-solid fa-arrow-up-right-from-square"></i> View source</a>`;
            container.appendChild(createResultItem(exp.title, desc, data.source || "Public vulnerability data"));
        });
    } else {
        container.innerHTML = '<p style="padding: 10px; color: var(--text-secondary);">No specific exploit links found by AI.</p>';
    }
    
    // Add external fallbacks too
    const fallbackSection = createSection('External Search');
    const fallbackContainer = fallbackSection.querySelector('.section-items');
    const links = `
        <div style="display: flex; gap: 10px; flex-wrap: wrap; padding: 5px;">
            <a href="https://www.exploit-db.com/search?q=${encodeURIComponent(query)}" target="_blank" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 8px;"><i class="fa-solid fa-record-vinyl"></i> Exploit-DB</a>
            <a href="https://github.com/search?q=${encodeURIComponent(query)}+exploit" target="_blank" class="btn btn-secondary" style="padding: 8px 16px; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 8px;"><i class="fa-brands fa-github"></i> GitHub</a>
        </div>
    `;
    fallbackContainer.appendChild(createResultItem("Manual Verification", links));
    
    resultsContent.appendChild(section);
    resultsContent.appendChild(fallbackSection);
}
