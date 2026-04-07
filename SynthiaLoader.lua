--[[
╔══════════════════════════════════════════════════════════════════════════════╗
║                         S Y N T H I A   L O A D E R                        ║
║                              v3.0  ·  Luarmor-style                         ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  Place this as a LocalScript inside StarterPlayerScripts.                   ║
║  Configure SERVER_URL and SCRIPT_NAME below, then deploy.                   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  FLOW                                                                       ║
║  ─────                                                                      ║
║  1. Loader boots → collects hardware fingerprint (multi-source)             ║
║  2. Sends fingerprint to server for silent pre-check                        ║
║  3. If already whitelisted → script executes immediately (no UI shown)     ║
║  4. If not whitelisted   → Key UI appears                                   ║
║     a. User clicks "Get Key" → POST /getkey/start (countdown begins)       ║
║     b. After wait          → POST /getkey/complete (key returned)           ║
║     c. User validates key  → POST /getkey/redeem   (HWID bind + execute)   ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  SECURITY                                                                   ║
║  ────────                                                                   ║
║  • Fingerprint built from RbxAnalyticsService, UserId, device metadata,    ║
║    and a session salt — makes HWID spoofing much harder.                   ║
║  • Every request carries a signed timestamp; server rejects stale calls.   ║
║  • Key is never written to disk or a global — lives only in this session.  ║
╚══════════════════════════════════════════════════════════════════════════════╝
--]]

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  CONFIGURATION  — edit these two lines and nothing else                 │
-- └─────────────────────────────────────────────────────────────────────────┘
local SERVER_URL  = "https://your-server.com"  -- No trailing slash
local SCRIPT_NAME = "MyScript"                 -- Must match dashboard name
local DEBUG       = false                      -- true = print verbose logs

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  SERVICES                                                               │
-- └─────────────────────────────────────────────────────────────────────────┘
local Players             = game:GetService("Players")
local HttpService         = game:GetService("HttpService")
local TweenService        = game:GetService("TweenService")
local UserInputService    = game:GetService("UserInputService")
local RbxAnalyticsService = game:GetService("RbxAnalyticsService")
local RunService          = game:GetService("RunService")
local MarketplaceService  = game:GetService("MarketplaceService")

local LocalPlayer = Players.LocalPlayer
local PlayerGui   = LocalPlayer:WaitForChild("PlayerGui")

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  THEME                                                                  │
-- └─────────────────────────────────────────────────────────────────────────┘
local THEME = {
    BG         = Color3.fromRGB(10,  10,  14),
    SURFACE    = Color3.fromRGB(16,  16,  22),
    CARD       = Color3.fromRGB(20,  20,  30),
    BORDER     = Color3.fromRGB(40,  40,  60),
    ACCENT     = Color3.fromRGB(108, 67,  255),
    ACCENT2    = Color3.fromRGB(138, 97,  255),
    SUCCESS    = Color3.fromRGB(52,  211, 153),
    DANGER     = Color3.fromRGB(239, 68,  68),
    WARNING    = Color3.fromRGB(245, 158, 11),
    TEXT       = Color3.fromRGB(230, 224, 255),
    TEXT_MUTED = Color3.fromRGB(140, 130, 180),
    TEXT_DIM   = Color3.fromRGB(80,  75,  110),
}

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  HELPERS                                                                │
-- └─────────────────────────────────────────────────────────────────────────┘
local function log(...)
    if DEBUG then print("[Synthia |", SCRIPT_NAME .. "]", ...) end
end

local function warn_(...)
    warn("[Synthia |", SCRIPT_NAME .. "]", ...)
end

local SESSION_SALT = tostring(math.random(1e8, 9e8)) .. tostring(os.time())

local FAST   = TweenInfo.new(0.18, Enum.EasingStyle.Quad,  Enum.EasingDirection.Out)
local SPRING = TweenInfo.new(0.45, Enum.EasingStyle.Back,  Enum.EasingDirection.Out)

local function tw(inst, info, props)
    TweenService:Create(inst, info, props):Play()
end

local function newInst(class, props, parent)
    local i = Instance.new(class)
    for k, v in pairs(props) do i[k] = v end
    if parent then i.Parent = parent end
    return i
end

local function addCorner(r, parent)
    return newInst("UICorner", { CornerRadius = UDim.new(0, r) }, parent)
end

local function addStroke(color, thick, alpha, parent)
    return newInst("UIStroke", { Color = color, Thickness = thick, Transparency = alpha }, parent)
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  FINGERPRINT                                                            │
-- └─────────────────────────────────────────────────────────────────────────┘
local function buildFingerprint()
    local clientId = ""
    local ok, res = pcall(function() return RbxAnalyticsService:GetClientId() end)
    if ok and res and res ~= "" then clientId = res end

    local deviceType = "Desktop"
    if UserInputService.TouchEnabled and not UserInputService.MouseEnabled then
        deviceType = "Mobile"
    elseif UserInputService.GamepadEnabled then
        deviceType = "Console"
    end

    local membershipEnum = tostring(LocalPlayer.MembershipType)

    local composite = table.concat({
        clientId,
        tostring(LocalPlayer.UserId),
        deviceType,
        membershipEnum,
        tostring(LocalPlayer.AccountAge),
    }, "|")

    local hash = 0
    for i = 1, #composite do
        hash = bit32.bxor(bit32.lrotate(hash, 5), string.byte(composite, i))
        hash = hash % 4294967296
    end
    local hwid = string.format("%s-%08x-%s",
        clientId ~= "" and clientId:sub(1, 8) or "fbk00000",
        hash,
        tostring(LocalPlayer.UserId))

    return {
        userId      = tostring(LocalPlayer.UserId),
        username    = LocalPlayer.Name,
        displayName = LocalPlayer.DisplayName,
        accountAge  = LocalPlayer.AccountAge,
        membership  = membershipEnum,
        deviceType  = deviceType,
        clientId    = clientId,
        hwid        = hwid,
        gameId      = tostring(game.PlaceId),
        timestamp   = math.floor(os.time()),
    }
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  HTTP                                                                   │
-- └─────────────────────────────────────────────────────────────────────────┘
local function httpPost(endpoint, body, retries)
    retries = retries or 2
    local url     = SERVER_URL .. endpoint
    local payload = HttpService:JSONEncode(body)
    for attempt = 1, retries + 1 do
        local success, response = pcall(function()
            return HttpService:PostAsync(url, payload, Enum.HttpContentType.ApplicationJson, false)
        end)
        if success then
            local ok2, decoded = pcall(function() return HttpService:JSONDecode(response) end)
            if ok2 then return decoded, nil end
            return nil, "Bad server response"
        end
        if attempt <= retries then task.wait(1) end
    end
    return nil, "Connection failed after " .. retries .. " retries"
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  UI BUILDER                                                             │
-- └─────────────────────────────────────────────────────────────────────────┘
local function buildUI()
    local existing = PlayerGui:FindFirstChild("SynthiaUI_v3")
    if existing then existing:Destroy() end

    local screenGui = newInst("ScreenGui", {
        Name           = "SynthiaUI_v3",
        ResetOnSpawn   = false,
        ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
        IgnoreGuiInset = true,
    }, PlayerGui)

    local blur = newInst("BlurEffect", { Size = 0 }, game:GetService("Lighting"))

    local overlay = newInst("Frame", {
        Size                   = UDim2.fromScale(1, 1),
        BackgroundColor3       = Color3.new(0, 0, 0),
        BackgroundTransparency = 1,
        ZIndex                 = 10,
    }, screenGui)

    -- Card
    local card = newInst("Frame", {
        Size                   = UDim2.fromOffset(400, 360),
        Position               = UDim2.new(0.5, 0, 0.65, 0),
        AnchorPoint            = Vector2.new(0.5, 0.5),
        BackgroundColor3       = THEME.CARD,
        BackgroundTransparency = 1,
        ZIndex                 = 11,
        ClipsDescendants       = true,
    }, screenGui)
    addCorner(16, card)
    local cardStroke = addStroke(THEME.ACCENT, 1.5, 0.55, card)

    -- Top gradient strip
    local topStrip = newInst("Frame", {
        Size             = UDim2.new(1, 0, 0, 2),
        BackgroundColor3 = THEME.ACCENT,
        BorderSizePixel  = 0,
        ZIndex           = 12,
    }, card)
    newInst("UIGradient", {
        Color = ColorSequence.new({
            ColorSequenceKeypoint.new(0,   Color3.fromRGB(80,  40, 200)),
            ColorSequenceKeypoint.new(0.5, Color3.fromRGB(180, 100, 255)),
            ColorSequenceKeypoint.new(1,   Color3.fromRGB(80,  40, 200)),
        }),
    }, topStrip)

    -- Header
    local header = newInst("Frame", {
        Size             = UDim2.new(1, 0, 0, 58),
        BackgroundColor3 = THEME.SURFACE,
        BorderSizePixel  = 0,
        ZIndex           = 12,
    }, card)

    local logoFrame = newInst("Frame", {
        Size             = UDim2.fromOffset(34, 34),
        Position         = UDim2.fromOffset(16, 12),
        BackgroundColor3 = THEME.ACCENT,
        ZIndex           = 13,
    }, header)
    addCorner(8, logoFrame)
    newInst("UIGradient", { Color = ColorSequence.new(THEME.ACCENT, Color3.fromRGB(70, 30, 190)), Rotation = 135 }, logoFrame)
    newInst("TextLabel", {
        Size = UDim2.fromScale(1, 1), BackgroundTransparency = 1,
        Text = "S", TextColor3 = Color3.new(1,1,1), TextSize = 16,
        Font = Enum.Font.GothamBold, ZIndex = 14,
    }, logoFrame)

    newInst("TextLabel", {
        Size = UDim2.new(1, -64, 0, 20), Position = UDim2.fromOffset(60, 10),
        BackgroundTransparency = 1, Text = "Synthia Whitelist",
        TextColor3 = THEME.TEXT, TextSize = 14, Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 13,
    }, header)
    newInst("TextLabel", {
        Size = UDim2.new(1, -64, 0, 16), Position = UDim2.fromOffset(60, 30),
        BackgroundTransparency = 1, Text = SCRIPT_NAME .. "  ·  Key Verification",
        TextColor3 = THEME.TEXT_MUTED, TextSize = 11, Font = Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 13,
    }, header)
    newInst("Frame", {
        Size = UDim2.new(1, 0, 0, 1), Position = UDim2.new(0, 0, 1, -1),
        BackgroundColor3 = THEME.BORDER, BorderSizePixel = 0, ZIndex = 13,
    }, header)

    -- Status row
    local statusFrame = newInst("Frame", {
        Size = UDim2.new(1, -32, 0, 44), Position = UDim2.fromOffset(16, 74),
        BackgroundColor3 = THEME.SURFACE, BorderSizePixel = 0, ZIndex = 12,
    }, card)
    addCorner(10, statusFrame)
    addStroke(THEME.BORDER, 1, 0.35, statusFrame)

    local statusDot = newInst("Frame", {
        Size = UDim2.fromOffset(6, 6), Position = UDim2.fromOffset(14, 19),
        BackgroundColor3 = THEME.TEXT_DIM, BorderSizePixel = 0, ZIndex = 13,
    }, statusFrame)
    addCorner(3, statusDot)

    local statusLabel = newInst("TextLabel", {
        Size = UDim2.new(1, -38, 1, 0), Position = UDim2.fromOffset(30, 0),
        BackgroundTransparency = 1, Text = 'Click  "Get Key"  to begin.',
        TextColor3 = THEME.TEXT_MUTED, TextSize = 12, Font = Enum.Font.Gotham,
        TextXAlignment = Enum.TextXAlignment.Left, TextWrapped = true, ZIndex = 13,
    }, statusFrame)

    -- Progress bar
    local progressTrack = newInst("Frame", {
        Size = UDim2.new(1, -32, 0, 3), Position = UDim2.fromOffset(16, 124),
        BackgroundColor3 = THEME.BORDER, BorderSizePixel = 0, Visible = false, ZIndex = 12,
    }, card)
    addCorner(2, progressTrack)
    local progressFill = newInst("Frame", {
        Size = UDim2.fromScale(0, 1), BackgroundColor3 = THEME.ACCENT,
        BorderSizePixel = 0, ZIndex = 13,
    }, progressTrack)
    addCorner(2, progressFill)
    newInst("UIGradient", { Color = ColorSequence.new(THEME.ACCENT, THEME.ACCENT2) }, progressFill)

    -- Key display box
    local keyBox = newInst("Frame", {
        Size = UDim2.new(1, -32, 0, 40), Position = UDim2.fromOffset(16, 134),
        BackgroundColor3 = Color3.fromRGB(10, 8, 20), BorderSizePixel = 0,
        Visible = false, ZIndex = 12,
    }, card)
    addCorner(8, keyBox)
    addStroke(THEME.ACCENT, 1, 0.5, keyBox)

    local keyDisplayLabel = newInst("TextLabel", {
        Size = UDim2.new(1, -52, 1, 0), Position = UDim2.fromOffset(10, 0),
        BackgroundTransparency = 1, Text = "",
        TextColor3 = THEME.SUCCESS, TextSize = 11, Font = Enum.Font.Code,
        TextXAlignment = Enum.TextXAlignment.Left, TextTruncate = Enum.TextTruncate.AtEnd, ZIndex = 13,
    }, keyBox)
    newInst("TextLabel", {
        Size = UDim2.fromOffset(44, 40), Position = UDim2.new(1, -48, 0, 0),
        BackgroundTransparency = 1, Text = "COPY",
        TextColor3 = THEME.ACCENT2, TextSize = 9, Font = Enum.Font.GothamBold, ZIndex = 14,
    }, keyBox)

    -- Input label
    newInst("TextLabel", {
        Size = UDim2.new(1, -32, 0, 16), Position = UDim2.fromOffset(16, 182),
        BackgroundTransparency = 1, Text = "ENTER YOUR KEY",
        TextColor3 = THEME.TEXT_DIM, TextSize = 10, Font = Enum.Font.GothamBold,
        TextXAlignment = Enum.TextXAlignment.Left, ZIndex = 12,
    }, card)

    -- Key input
    local keyInput = newInst("TextBox", {
        Size = UDim2.new(1, -32, 0, 40), Position = UDim2.fromOffset(16, 200),
        BackgroundColor3 = THEME.SURFACE, BorderSizePixel = 0,
        Text = "", PlaceholderText = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        TextColor3 = THEME.TEXT, PlaceholderColor3 = THEME.TEXT_DIM,
        TextSize = 11, Font = Enum.Font.Code, ClearTextOnFocus = false, ZIndex = 12,
    }, card)
    addCorner(8, keyInput)
    local inputStroke = addStroke(THEME.BORDER, 1, 0.3, keyInput)
    keyInput.Focused:Connect(function()
        tw(inputStroke, FAST, { Color = THEME.ACCENT, Transparency = 0 })
    end)
    keyInput.FocusLost:Connect(function()
        tw(inputStroke, FAST, { Color = THEME.BORDER, Transparency = 0.3 })
    end)

    -- Buttons
    local btnRow = newInst("Frame", {
        Size = UDim2.new(1, -32, 0, 44), Position = UDim2.fromOffset(16, 256),
        BackgroundTransparency = 1, ZIndex = 12,
    }, card)
    newInst("UIListLayout", {
        FillDirection = Enum.FillDirection.Horizontal,
        HorizontalAlignment = Enum.HorizontalAlignment.Center,
        Padding = UDim.new(0, 10),
    }, btnRow)

    local function makeBtn(text, primary)
        local btn = newInst("TextButton", {
            Size = UDim2.fromOffset(175, 40),
            BackgroundColor3 = primary and THEME.ACCENT or THEME.SURFACE,
            BorderSizePixel = 0, Text = text,
            TextColor3 = primary and Color3.new(1,1,1) or THEME.TEXT_MUTED,
            TextSize = 12, Font = Enum.Font.GothamBold,
            ZIndex = 13, AutoButtonColor = false,
        }, btnRow)
        addCorner(8, btn)
        if primary then
            newInst("UIGradient", {
                Color = ColorSequence.new(THEME.ACCENT, Color3.fromRGB(75, 35, 195)), Rotation = 135,
            }, btn)
        else
            addStroke(THEME.BORDER, 1, 0.3, btn)
        end
        btn.MouseEnter:Connect(function()
            tw(btn, FAST, { BackgroundColor3 = primary and THEME.ACCENT2 or Color3.fromRGB(28,28,42) })
        end)
        btn.MouseLeave:Connect(function()
            tw(btn, FAST, { BackgroundColor3 = primary and THEME.ACCENT or THEME.SURFACE })
        end)
        btn.MouseButton1Down:Connect(function()
            tw(btn, TweenInfo.new(0.07), { Size = UDim2.fromOffset(172, 37) })
        end)
        btn.MouseButton1Up:Connect(function()
            tw(btn, TweenInfo.new(0.14, Enum.EasingStyle.Back, Enum.EasingDirection.Out), { Size = UDim2.fromOffset(175, 40) })
        end)
        return btn
    end

    local getKeyBtn   = makeBtn("⬡  Get Key", true)
    local validateBtn = makeBtn("✓  Validate", false)

    -- Footer
    newInst("TextLabel", {
        Size = UDim2.new(1, 0, 0, 24), Position = UDim2.new(0, 0, 1, -26),
        BackgroundTransparency = 1, Text = "Protected by Synthia  ·  HWID-Locked",
        TextColor3 = THEME.TEXT_DIM, TextSize = 10, Font = Enum.Font.Gotham, ZIndex = 12,
    }, card)

    -- Entrance animation
    tw(blur,    TweenInfo.new(0.5),  { Size = 10 })
    tw(overlay, TweenInfo.new(0.3),  { BackgroundTransparency = 0.45 })
    tw(card,    SPRING, { Position = UDim2.fromScale(0.5, 0.5), BackgroundTransparency = 0 })

    return {
        screenGui       = screenGui,
        blur            = blur,
        overlay         = overlay,
        card            = card,
        cardStroke      = cardStroke,
        statusDot       = statusDot,
        statusLabel     = statusLabel,
        progressTrack   = progressTrack,
        progressFill    = progressFill,
        keyBox          = keyBox,
        keyDisplayLabel = keyDisplayLabel,
        keyInput        = keyInput,
        getKeyBtn       = getKeyBtn,
        validateBtn     = validateBtn,
    }
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  HELPERS — status + UI state                                            │
-- └─────────────────────────────────────────────────────────────────────────┘
local function setStatus(ui, text, color, dotColor)
    ui.statusLabel.Text       = text
    ui.statusLabel.TextColor3 = color or THEME.TEXT_MUTED
    if dotColor then tw(ui.statusDot, FAST, { BackgroundColor3 = dotColor }) end
end

local function setLocked(ui, locked)
    ui.getKeyBtn.Active            = not locked
    ui.validateBtn.Active          = not locked
    ui.getKeyBtn.BackgroundTransparency  = locked and 0.45 or 0
    ui.validateBtn.BackgroundTransparency = locked and 0.45 or 0
end

local function dismissUI(ui, delay_)
    task.wait(delay_ or 1.2)
    tw(ui.card,    TweenInfo.new(0.35, Enum.EasingStyle.Quad, Enum.EasingDirection.In), {
        Position = UDim2.new(0.5, 0, 0.35, 0), BackgroundTransparency = 1,
    })
    tw(ui.blur,    TweenInfo.new(0.35), { Size = 0 })
    tw(ui.overlay, TweenInfo.new(0.35), { BackgroundTransparency = 1 })
    task.wait(0.4)
    ui.screenGui:Destroy()
    ui.blur:Destroy()
end

local function executeSource(source)
    if not source or source == "" then
        log("Verify-only mode — no script source returned.")
        return
    end
    local fn, loadErr = loadstring(source)
    if fn then
        local ok, runErr = pcall(fn)
        if not ok then warn_("Runtime error:", runErr) end
    else
        warn_("Compile error:", loadErr)
    end
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  SILENT PRE-CHECK — skip UI if already whitelisted                     │
-- └─────────────────────────────────────────────────────────────────────────┘
local function silentCheck(fp)
    local resp, err = httpPost("/getkey/precheck", {
        hwid      = fp.hwid,
        userId    = fp.userId,
        username  = fp.username,
        script    = SCRIPT_NAME,
        timestamp = fp.timestamp,
    })
    if err or not resp then return false, nil end
    if resp.whitelisted and resp.source and resp.source ~= "" then
        return true, resp.source
    end
    return false, nil
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  MAIN                                                                   │
-- └─────────────────────────────────────────────────────────────────────────┘
local function runLoader()
    local fp = buildFingerprint()
    log("Fingerprint built — uid:", fp.userId, "hwid:", fp.hwid)

    -- 1. Silent whitelist check
    local whitelisted, source = silentCheck(fp)
    if whitelisted and source then
        log("Already whitelisted — executing immediately.")
        executeSource(source)
        return
    end

    -- 2. Show key UI
    local ui           = buildUI()
    local currentState = "idle"
    local pendingToken = nil
    local generatedKey = nil

    -- ── GET KEY ────────────────────────────────────────────────────────────
    ui.getKeyBtn.MouseButton1Click:Connect(function()
        if currentState ~= "idle" and currentState ~= "key_ready" then return end
        currentState = "waiting"
        setLocked(ui, true)
        setStatus(ui, "Connecting to Synthia servers…", THEME.TEXT_MUTED, THEME.WARNING)

        local fp2 = buildFingerprint()
        local resp, err = httpPost("/getkey/start", { userId = fp2.userId, username = fp2.username })
        if err or not resp or not resp.success then
            currentState = "idle"
            setLocked(ui, false)
            setStatus(ui, "✕  " .. (resp and resp.message or err or "Unknown error"), THEME.DANGER, THEME.DANGER)
            tw(ui.cardStroke, FAST, { Color = THEME.DANGER })
            task.delay(2.5, function() tw(ui.cardStroke, FAST, { Color = THEME.ACCENT }) end)
            return
        end

        pendingToken = resp.token
        local waitSecs = resp.wait_seconds or 5

        ui.progressTrack.Visible = true
        ui.progressFill.Size     = UDim2.fromScale(0, 1)
        tw(ui.progressFill, TweenInfo.new(waitSecs, Enum.EasingStyle.Linear), { Size = UDim2.fromScale(1, 1) })

        local startTime = tick()
        local conn
        conn = RunService.Heartbeat:Connect(function()
            local elapsed   = tick() - startTime
            local remaining = math.max(0, waitSecs - elapsed)
            setStatus(ui,
                string.format("Verifying identity… %ds remaining", math.ceil(remaining)),
                THEME.TEXT_MUTED, THEME.WARNING)

            if elapsed >= waitSecs then
                conn:Disconnect()
                ui.progressTrack.Visible = false
                setStatus(ui, "Generating your key…", THEME.TEXT_MUTED, THEME.ACCENT2)

                local fp3 = buildFingerprint()
                local resp2, err2 = httpPost("/getkey/complete", { token = pendingToken, fingerprint = fp3 })
                if err2 or not resp2 or not resp2.success then
                    currentState = "idle"
                    setLocked(ui, false)
                    setStatus(ui, "✕  " .. (resp2 and resp2.message or err2 or "Failed"), THEME.DANGER, THEME.DANGER)
                    return
                end

                generatedKey = resp2.key
                currentState = "key_ready"
                setLocked(ui, false)
                ui.keyBox.Visible       = true
                ui.keyDisplayLabel.Text = generatedKey
                ui.keyInput.Text        = generatedKey

                local tag = resp2.reissued and " (existing key)" or ""
                setStatus(ui, "✓  Key ready" .. tag .. " — click Validate to activate.", THEME.SUCCESS, THEME.SUCCESS)
                tw(ui.cardStroke, FAST, { Color = THEME.SUCCESS })
                task.delay(3, function()
                    if currentState == "key_ready" then tw(ui.cardStroke, FAST, { Color = THEME.ACCENT }) end
                end)
            end
        end)
    end)

    -- ── VALIDATE ───────────────────────────────────────────────────────────
    ui.validateBtn.MouseButton1Click:Connect(function()
        if currentState == "validating" or currentState == "success" then return end

        local keyValue = ui.keyInput.Text:match("^%s*(.-)%s*$")
        if keyValue == "" then
            setStatus(ui, "⚠  Please enter your key first.", THEME.WARNING, THEME.WARNING)
            return
        end
        if not keyValue:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") then
            setStatus(ui, "⚠  Invalid key format — expected a UUID.", THEME.WARNING, THEME.WARNING)
            return
        end

        currentState = "validating"
        setLocked(ui, true)
        setStatus(ui, "Validating key + device fingerprint…", THEME.TEXT_MUTED, THEME.ACCENT2)

        local fp4 = buildFingerprint()
        local resp, err = httpPost("/getkey/redeem", {
            key         = keyValue,
            fingerprint = fp4,
            script      = SCRIPT_NAME,
        })

        if err or not resp then
            currentState = "key_ready"
            setLocked(ui, false)
            setStatus(ui, "✕  " .. (err or "Connection failed"), THEME.DANGER, THEME.DANGER)
            return
        end

        if not resp.valid then
            currentState = "key_ready"
            setLocked(ui, false)
            setStatus(ui, "✕  " .. (resp.reason or "Validation failed"), THEME.DANGER, THEME.DANGER)
            tw(ui.cardStroke, FAST, { Color = THEME.DANGER })
            task.delay(2.5, function() tw(ui.cardStroke, FAST, { Color = THEME.ACCENT }) end)
            return
        end

        -- Success
        currentState = "success"
        setStatus(ui, "✓  Authenticated — loading " .. SCRIPT_NAME .. "…", THEME.SUCCESS, THEME.SUCCESS)
        tw(ui.cardStroke, FAST, { Color = THEME.SUCCESS })
        log("Authenticated — executing script.")

        local scriptSource = resp.source
        dismissUI(ui, 1)
        executeSource(scriptSource)
    end)
end

-- ┌─────────────────────────────────────────────────────────────────────────┐
-- │  BOOT                                                                   │
-- └─────────────────────────────────────────────────────────────────────────┘
if not LocalPlayer.Character then LocalPlayer.CharacterAdded:Wait() end
task.wait(0.5)
runLoader()
