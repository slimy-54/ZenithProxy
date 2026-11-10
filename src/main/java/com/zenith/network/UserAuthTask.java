package com.zenith.network;

import com.zenith.feature.api.sessionserver.SessionServerApi;
import com.zenith.network.server.ServerSession;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.protocol.packet.login.clientbound.ClientboundLoginCompressionPacket;
import org.geysermc.mcprotocollib.protocol.packet.login.clientbound.ClientboundLoginFinishedPacket;
import com.zenith.util.config.Config;

import javax.crypto.SecretKey;
import java.util.Optional;

import static com.zenith.Globals.CONFIG;
import static com.zenith.Globals.SERVER_LOG;

public class UserAuthTask implements Runnable {
    private final ServerSession session;
    private final SecretKey key;

    public UserAuthTask(ServerSession session, SecretKey key) {
        this.key = key;
        this.session = session;
    }

    @Override
    public void run() {
        GameProfile profile;
        // Player -> proxy authentication is configured independently from
        // proxy -> upstream server authentication (CONFIG.authentication.accountType).
        if (CONFIG.server.verifyUsers) {
            // Online mode: the client must complete a Mojang session verification.
            // Offline/cracked clients cannot pass this check.
            if (this.key == null) {
                this.session.disconnect("No encryption key!");
                return;
            }
            final Optional<GameProfile> response = SessionServerApi.INSTANCE.hasJoined(
                session.getUsername(),
                SessionServerApi.INSTANCE.getSharedSecret(
                    session.getServerId(),
                    session.getKeyPair().getPublic(),
                    this.key));
            if (response.isEmpty()) {
                this.session.disconnect("Failed to verify username.");
                return;
            }
            profile = response.get();
        } else {
            // Offline mode: accept any username. Access is controlled by the
            // whitelist/blacklist in SLoginFinishedOutgoingHandler.
            profile = new GameProfile(
                Config.Authentication.generateOfflineUUID(session.getUsername()),
                session.getUsername());
            SERVER_LOG.info("Offline client authenticated: {} [{}]", profile.getName(), profile.getId());
        }
        session.getProfileCache().setProfile(profile);

        final var threshold = CONFIG.server.compressionThreshold;
        if (threshold >= 0) {
            this.session.send(new ClientboundLoginCompressionPacket(threshold));
        } else {
            session.setCompressionThreshold(threshold, CONFIG.server.compressionLevel, true);
            session.send(new ClientboundLoginFinishedPacket(profile));
        }
    }
}
