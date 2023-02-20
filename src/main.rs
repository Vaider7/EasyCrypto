use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use iced::alignment::{Horizontal, Vertical};
use iced::widget::{button, column, container, row, text, text_input};
use iced::{
    executor, theme, window, Alignment, Application, Color, Command, Element, Length, Renderer,
    Settings, Theme,
};
use std::env::current_dir;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use rand::distributions::{Alphanumeric, DistString};

const NONCE: &str = "fhd6sk4jfh4n";

#[derive(Clone, Debug)]
enum State {
    Crypt,
    Decrypt,
}

#[derive(Default)]
struct EasyCrypto {
    state: Option<State>,
    chosen_dir: Option<PathBuf>,
    key: String,
    repeated_key: String,
    wrong_message: String,
}

#[derive(Debug, Clone)]
enum Message {
    ChooseDirectory(State),
    Key(String),
    RepeatKey(String),
    Crypt,
    Decrypt,
    Back,
    Wrong(String),
    ToggleProcess
}

impl Application for EasyCrypto {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (EasyCrypto, Command<Message>) {
        (EasyCrypto::default(), Command::none())
    }

    fn title(&self) -> String {
        "Easy Crypto".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        self.wrong_message.clear();
        match message {
            Message::ToggleProcess => {
                self.state = None;
            },
            Message::Key(input) => self.key = input,
            Message::RepeatKey(input) => self.repeated_key = input,
            Message::ChooseDirectory(state) => {
                self.chosen_dir = rfd::FileDialog::new()
                    .set_directory(current_dir().unwrap().as_path())
                    .pick_folder();
                self.state = Some(state)
            }
            Message::Wrong(wrong_message) => self.wrong_message = wrong_message,
            Message::Crypt => {
                if self.key.len() > 32 {
                    return self.update(Message::Wrong(
                        "Длина ключа должна быть не более 32 символов".to_string(),
                    ));
                }

                if self.key != self.repeated_key {
                    return self.update(Message::Wrong("Ключи не совпадают".to_string()));
                }

                self.update(Message::ToggleProcess);

                let mut fixed_len = self.key.clone();
                for _ in 0..32 - fixed_len.len() {
                    fixed_len.push('0');
                }

                if let Err(e) = EasyCrypto::encrypt_folder(
                    self.chosen_dir.as_ref().unwrap(),
                    fixed_len.as_bytes(),
                    0,
                ) {
                    return match e {
                        EncryptError::FS(fs_err) => {
                            self.update(Message::Wrong(format!("Произошла ошибка: {fs_err}")));
                            Command::none()
                        }
                        EncryptError::Crypto(crypto) => {
                            self.update(Message::Wrong(format!("Произошла ошибка: {crypto}")));
                            Command::none()
                        }
                    };
                }
                self.key.clear();
                self.repeated_key.clear();
            }
            Message::Decrypt => {
                let mut fixed_len = self.key.clone();
                for _ in 0..32 - fixed_len.len() {
                    fixed_len.push('0');
                }

                self.update(Message::ToggleProcess);

                if let Err(e) = EasyCrypto::decrypt_folder(
                    self.chosen_dir.as_ref().unwrap(),
                    fixed_len.as_bytes(),
                    0,
                ) {
                    return match e {
                        EncryptError::FS(fs_err) => {
                            self.update(Message::Wrong(format!("Произошла ошибка: {fs_err}")));
                            Command::none()
                        }
                        EncryptError::Crypto(_crypto) => {
                            self.update(Message::Wrong(format!("Неверный ключ")));
                            Command::none()
                        }
                    };
                }
                self.key.clear();
                self.repeated_key.clear();
            }

            Message::Back => {
                self.chosen_dir = None;
                self.key.clear();
                self.repeated_key.clear();
            }
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message, Renderer<Self::Theme>> {
        if let Some(state) = &self.state {
            if let Some(chosen_dir) = &self.chosen_dir {
                return match state {
                    State::Crypt => {
                        let title = text("Выбранный путь: ".to_string());

                        let chosen_dir = text(&chosen_dir.to_str().unwrap().to_string());

                        let key = text_input("Введите ключ", &self.key, Message::Key).password();

                        let repeated_key =
                            text_input("Повторите ключ", &self.repeated_key, Message::RepeatKey)
                                .password();

                        let crypt = button("Зашифровать")
                            .padding([10, 5])
                            .on_press(Message::Crypt)
                            .width(Length::FillPortion(1));

                        let back = button("Назад")
                            .style(theme::Button::Destructive)
                            .on_press(Message::Back)
                            .width(Length::FillPortion(1))
                            .padding([10, 5]);

                        let row = row![back, crypt]
                            .width(Length::Fill)
                            .align_items(Alignment::Fill)
                            .spacing(50);

                        let wrong_message = text(&self.wrong_message)
                            .style(theme::Text::Color(Color::from([1.0, 0.0, 0.0])))
                            .horizontal_alignment(Horizontal::Center)
                            .vertical_alignment(Vertical::Center);

                        let column =
                            column![title, chosen_dir, key, repeated_key, row, wrong_message]
                                .width(Length::Units(400))
                                .spacing(20);

                        container(column)
                            .center_x()
                            .center_y()
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .into()
                    }

                    State::Decrypt => {
                        let title = text("Выбранный путь: ".to_string());

                        let chosen_dir = text(&chosen_dir.to_str().unwrap().to_string());

                        let key = text_input("Введите ключ", &self.key, Message::Key).password();

                        let decrypt = button("Расшифровать")
                            .padding([10, 5])
                            .on_press(Message::Decrypt)
                            .width(Length::FillPortion(1));

                        let back = button("Назад")
                            .style(theme::Button::Destructive)
                            .on_press(Message::Back)
                            .width(Length::FillPortion(1))
                            .padding([10, 5]);

                        let wrong_message = text(&self.wrong_message)
                            .style(theme::Text::Color(Color::from([1.0, 0.0, 0.0])))
                            .horizontal_alignment(Horizontal::Center)
                            .vertical_alignment(Vertical::Center);

                        let row = row![back, decrypt]
                            .width(Length::Fill)
                            .align_items(Alignment::Fill)
                            .spacing(50);

                        let column = column![title, chosen_dir, key, row, wrong_message]
                            .width(Length::Units(400))
                            .spacing(20);

                        container(column)
                            .center_x()
                            .center_y()
                            .width(Length::Fill)
                            .height(Length::Fill)
                            .into()
                    }
                };
            }
        }

        let crypt = button("Зашифровать")
            .padding([10, 5])
            .on_press(Message::ChooseDirectory(State::Crypt));
        let decrypt = button("Расшифровать")
            .padding([10, 5])
            .on_press(Message::ChooseDirectory(State::Decrypt));

        let row = row![crypt, decrypt]
            .spacing(20)
            .align_items(Alignment::Fill);

        container(row)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .padding(20)
            .into()



    }
    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

enum EncryptError {
    FS(io::Error),
    Crypto(chacha20poly1305::Error),
}

impl From<chacha20poly1305::Error> for EncryptError {
    fn from(err: chacha20poly1305::Error) -> Self {
        EncryptError::Crypto(err)
    }
}

impl From<io::Error> for EncryptError {
    fn from(err: io::Error) -> Self {
        EncryptError::FS(err)
    }
}

impl EasyCrypto {
    fn decrypt_folder(
        chosen_dir: &PathBuf,
        key: &[u8],
        mut recursion_depth: u16,
    ) -> Result<(), EncryptError> {
        let (staged_dir, random_postfix) = staged_dir(chosen_dir, recursion_depth);

        let files_to_decrypt = fs::read_dir(chosen_dir)?;

        fs::create_dir(&staged_dir)?;

        for dir_entry in files_to_decrypt {
            let to_decrypt = dir_entry?.path();

            if to_decrypt.is_dir() {
                recursion_depth += 1;
                Self::decrypt_folder(&to_decrypt, key, recursion_depth)?;
                recursion_depth -= 1;
                continue;
            }

            let decrypted_file_path = format!(
                "{}/{}",
                staged_dir,
                to_decrypt.file_name().unwrap().to_str().unwrap()
            );

            let file = fs::read(to_decrypt)?;

            let mut decrypted_file = fs::File::create(&decrypted_file_path)?;
            let key = Key::clone_from_slice(key);
            let cipher = ChaCha20Poly1305::new(&key);
            let deciphered_file =
                cipher.decrypt(&Nonce::clone_from_slice(NONCE.as_bytes()), file.as_ref());

            if let Err(err) = deciphered_file {
                fs::remove_dir_all(staged_dir)?;
                return Err(EncryptError::Crypto(err))
            }
            decrypted_file.write_all(deciphered_file.unwrap().as_ref())?;

        }
        let dir = staged_dir.trim_end_matches(format!("_{random_postfix}").as_str());
        fs::remove_dir_all(chosen_dir)?;
        fs::rename(&staged_dir, dir)?;
        Ok(())
    }

    fn encrypt_folder(
        chosen_dir: &PathBuf,
        key: &[u8],
        mut recursion_depth: u16,
    ) -> Result<(), EncryptError> {
        let (staged_dir, random_postfix) = staged_dir(chosen_dir, recursion_depth);

        fs::create_dir(&staged_dir)?;

        let files_to_encrypt = fs::read_dir(chosen_dir)?;

        for dir_entry in files_to_encrypt {
            let to_encrypt = dir_entry?.path();

            if to_encrypt.is_dir() {
                recursion_depth += 1;
                Self::encrypt_folder(&to_encrypt, key, recursion_depth)?;
                recursion_depth -= 1;
                continue;
            }

            let encrypted_file_path = format!(
                "{}/{}",
                staged_dir,
                to_encrypt.file_name().unwrap().to_str().unwrap()
            );

            let mut encrypted_file = fs::File::create(&encrypted_file_path)?;

            let file = fs::read(to_encrypt)?;

            let key = Key::clone_from_slice(key);
            let cipher = ChaCha20Poly1305::new(&key);
            let ciphered_file =
                cipher.encrypt(&Nonce::clone_from_slice(NONCE.as_bytes()), file.as_ref())?;

            encrypted_file.write_all(ciphered_file.as_ref())?;
        }
        let dir = staged_dir.trim_end_matches(format!("_{random_postfix}").as_str());
        fs::remove_dir_all(chosen_dir)?;
        fs::rename(&staged_dir, dir)?;
        Ok(())
    }
}

fn staged_dir(chosen_dir: &PathBuf, recursion_depth: u16) -> (String, String) {
    let random_postfix = Alphanumeric.sample_string(&mut rand::thread_rng(), 5);
    let mut staged_dir;
    if recursion_depth == 0 {
        staged_dir = format!("{}_{}", chosen_dir.display(), random_postfix);
    } else {
        let mut ancestors = chosen_dir.as_path().ancestors();

        let mut parent_dir_names = Vec::with_capacity(recursion_depth as usize);

        for _ in 0..=recursion_depth {
            parent_dir_names.push(format!(
                "/{}_{}",
                ancestors
                    .next()
                    .unwrap()
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                random_postfix
            ));
        }

        parent_dir_names.reverse();
        staged_dir = ancestors.next().unwrap().to_str().unwrap().to_string();
        for i in parent_dir_names.iter() {
            staged_dir.push_str(&i.to_string());
        }
    }
    (staged_dir, random_postfix)
}

fn main() -> iced::Result {
    EasyCrypto::run(Settings {
        window: window::Settings {
            size: (500, 350),
            ..window::Settings::default()
        },
        ..Settings::default()
    })
}
