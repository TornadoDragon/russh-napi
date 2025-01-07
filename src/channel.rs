use std::sync::Arc;

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use tokio::sync::oneshot;
use tokio::sync::Mutex;

use crate::error::WrappedError;

type ChannelType = russh::Channel<russh::client::Msg>;

#[napi]
pub struct SshChannel {
    waiter: Arc<Mutex<Option<ChannelWaiter>>>,
}

impl From<ChannelType> for SshChannel {
    fn from(ch: ChannelType) -> Self {
        SshChannel {
            waiter: Arc::new(Mutex::new(Some(ChannelWaiter::new(ch)))),
        }
    }
}

struct ChannelWaiter(oneshot::Receiver<ChannelType>, oneshot::Sender<()>);

impl ChannelWaiter {
    async fn inner_waiter(ch: &mut ChannelType) {
        while let Some(_) = ch.wait().await {}
    }

    async fn waiter(
        mut ch: ChannelType,
        cancel_rx: oneshot::Receiver<()>,
        return_tx: oneshot::Sender<ChannelType>,
    ) {
        tokio::select! {
            _ = Self::inner_waiter(&mut ch) => {}
            _ = cancel_rx => {}
        }
        let _ = return_tx.send(ch);
    }

    pub fn new(ch: ChannelType) -> Self {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        let (return_tx, return_rx) = oneshot::channel();
        tokio::spawn(Self::waiter(ch, cancel_rx, return_tx));
        Self(return_rx, cancel_tx)
    }

    pub async fn take(self) -> ChannelType {
        let _ = self.1.send(());
        self.0
            .await
            .expect("channel waiter did not return a channel")
    }
}

#[napi]
impl SshChannel {
    async fn take_expect<F, O>(&self, f: F) -> napi::Result<O>
    where
        F: AsyncFnOnce(&mut ChannelType) -> napi::Result<O>,
    {
        let mut ch = self.take().await.expect("channel is already consumed");
        let out = f(&mut ch).await?;
        *self.waiter.lock().await = Some(ChannelWaiter::new(ch));
        Ok(out)
    }

    pub async fn take(&self) -> Option<ChannelType> {
        match self.waiter.lock().await.take() {
            Some(x) => Some(x.take().await),
            None => None,
        }
    }

    #[napi]
    pub async fn id(&self) -> napi::Result<u32> {
        let id = self
            .take_expect(async move |handle| {
                let id: u32 = handle.id().into();
                Ok(id)
            })
            .await?;
        Ok(id)
    }

    #[napi]
    pub async fn request_pty(
        &self,
        term: String,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .request_pty(
                    false,
                    &term,
                    col_width,
                    row_height,
                    pix_width,
                    pix_height,
                    &[],
                )
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn request_shell(&self) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .request_shell(true)
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn request_exec(&self, command: String) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .exec(true, command)
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn request_x11_forwarding(
        &self,
        single_connection: bool,
        x11_protocol: String,
        x11_cookie: String,
        screen: u32,
    ) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .request_x11(false, single_connection, &x11_protocol, &x11_cookie, screen)
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn request_agent_forwarding(&self) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .agent_forward(false)
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn window_change(
        &self,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    ) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle
                .window_change(col_width, row_height, pix_width, pix_height)
                .await
                .map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn data(&self, data: Uint8Array) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle.data(&data[..]).await.map_err(|_| {
                napi::Error::new(
                    napi::Status::GenericFailure,
                    "Failed to send data to channel",
                )
            })?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn eof(&self) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle.eof().await.map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }

    #[napi]
    pub async fn close(&self) -> napi::Result<()> {
        self.take_expect(async move |handle| {
            handle.close().await.map_err(WrappedError::from)?;
            Ok(())
        })
        .await
    }
}
